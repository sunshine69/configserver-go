package backend

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// DefaultTableName is used when no table_name is specified in user config.
	DefaultTableName = "config_server_files"

	// TableSQL creates the schema if it does not already exist. It is
	// idempotent and safe to run on every startup.
	TableSQL = `
CREATE TABLE IF NOT EXISTS config_server_files (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(128) NOT NULL,
    app         VARCHAR(256) NOT NULL,
    profile     VARCHAR(256) NOT NULL,
    label       VARCHAR(256) NOT NULL DEFAULT '',
    ext         VARCHAR(16) NOT NULL,
    content     TEXT NOT NULL,
    path        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (username, app, profile, label, ext)
);
CREATE INDEX IF NOT EXISTS idx_config_server_files_lookup
    ON config_server_files (username, app, profile, label, ext);`
)

// PostgresBackend manages connection pools for all postgres-backed users.
//
// It is safe for concurrent use. Connections are pooled per DSN and lazily
// created on first use.
type PostgresBackend struct {
	mu        sync.RWMutex
	pools     map[string]*pgxpool.Pool // keyed by DSN
	globalDSN string
}

// NewPostgresBackend creates the global pool manager.
//
// globalDSN is the fallback DSN used when a user does not have their own
// connection_string configured. An empty string means only users with
// explicit connection strings can use postgres.
func NewPostgresBackend(globalDSN string) *PostgresBackend {
	return &PostgresBackend{
		pools:     make(map[string]*pgxpool.Pool),
		globalDSN: globalDSN,
	}
}

// ForUser returns a Backend bound to the given user's connection and table.
//
// The user's own connection_string (if set) takes priority over the global
// DSN. The table name defaults to DefaultTableName unless overridden.
func (b *PostgresBackend) ForUser(user UserBackend) (Backend, error) {
	dsn := b.resolveDSN(user)
	pool, err := b.getPool(dsn)
	if err != nil {
		return nil, err
	}
	table := resolveTableName(user)
	return &postgresUserBackend{
		db:       pool,
		table:    table,
		username: user.GetUsername(),
	}, nil
}

// CreateTempPool opens a one-shot connection pool for migrations.
// It does not cache the pool — the caller must Close it.
func (b *PostgresBackend) CreateTempPool(dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres DSN: %w", err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 0
	cfg.MaxConnLifetime = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("create temp pool: %w", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

// Close shuts down all managed connection pools. Safe to call multiple times.
func (b *PostgresBackend) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, pool := range b.pools {
		pool.Close()
	}
	b.pools = make(map[string]*pgxpool.Pool)
}

// ExpandEnvVars replaces ${VAR} patterns in the input string with the
// corresponding environment variable value. Supports the following syntaxes:
//   - ${VAR}          → value if set, else leave as-is
//   - ${VAR:-default} → value if set, else 'default'
//   - ${VAR:+other}   → 'other' if VAR is set, else empty
//
// This allows docker-compose to inject connection details at runtime without
// requiring hardcoded values in config.yaml.
func ExpandEnvVars(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			// Find the closing brace
			j := strings.IndexByte(s[i+2:], '}')
			if j < 0 {
				// No closing brace — leave as-is
				b.WriteByte('$')
				continue
			}

			// Extract the full expression: VAR, VAR:-default, or VAR:+other
			fullExpr := s[i+2 : i+2+j]

			var varName string
			var hasDefault, hasAlternative bool
			var defaultValue, alternativeValue string

			// Check for :- (default value)
			if idx := strings.Index(fullExpr, ":-"); idx >= 0 {
				varName = fullExpr[:idx]
				defaultValue = fullExpr[idx+2:]
				hasDefault = true
			} else if idx := strings.Index(fullExpr, ":+"); idx >= 0 {
				varName = fullExpr[:idx]
				alternativeValue = fullExpr[idx+2:]
				hasAlternative = true
			} else {
				varName = fullExpr
			}

			if val, ok := os.LookupEnv(varName); ok {
				if hasAlternative {
					// VAR is set, use alternative value
					b.WriteString(alternativeValue)
				} else {
					b.WriteString(val)
				}
			} else if hasDefault {
				// VAR is not set, use default value
				b.WriteString(defaultValue)
			} else {
				// VAR is not set, leave placeholder for libpq
				b.WriteString(s[i : i+2+j+1])
			}
			i = i + 2 + j
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// resolveDSN picks the DSN for a user: explicit first, then global fallback.
//
// It applies environment variable substitution (${PGHOST}, ${PGDATABASE}, …)
// so docker-compose can inject connection details at runtime.
func (b *PostgresBackend) resolveDSN(user UserBackend) string {
	dsn := b.globalDSN
	if user.GetPostgresDSN() != "" {
		dsn = user.GetPostgresDSN()
	}
	return ExpandEnvVars(dsn)
}

// resolveTableName picks the table name for a user.
func resolveTableName(user UserBackend) string {
	if user.GetPostgresTable() != "" {
		return user.GetPostgresTable()
	}
	return DefaultTableName
}

// getPool returns (and lazily creates) a connection pool for the given DSN.
func (b *PostgresBackend) getPool(dsn string) (*pgxpool.Pool, error) {
	b.mu.RLock()
	if pool, ok := b.pools[dsn]; ok {
		b.mu.RUnlock()
		return pool, nil
	}
	b.mu.RUnlock()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Double-check after acquiring write lock.
	if pool, ok := b.pools[dsn]; ok {
		return pool, nil
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres DSN: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", dsn, err)
	}

	b.pools[dsn] = pool
	return pool, nil
}

// postgresUserBackend is a Backend bound to one user in one table.
type postgresUserBackend struct {
	db       *pgxpool.Pool
	table    string
	username string
}

func (b *postgresUserBackend) GetFile(app, profile, label string, ext string) ([]byte, error) {
	q := fmt.Sprintf(
		"SELECT content FROM %s WHERE username=$1 AND app=$2 AND profile=$3 AND label=$4 AND ext=$5",
		b.table,
	)
	var content []byte
	err := b.db.QueryRow(context.Background(), q,
		b.username, app, profile, label, ext,
	).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("postgres GetFile: %w", err)
	}
	return content, nil
}

// GetFileByPath returns the file content stored under the given relative path.
// The path is stored in the 'path' column and was populated by PutFileWithFullPath.
func (b *postgresUserBackend) GetFileByPath(fullPath string) ([]byte, error) {
	// Clean the path: remove leading/trailing slashes, reject traversal.
	cleanPath := strings.Trim(fullPath, "/")
	if !IsValidRelativePath(cleanPath) {
		return nil, fmt.Errorf("invalid path: %s", fullPath)
	}

	q := fmt.Sprintf(
		"SELECT content FROM %s WHERE username=$1 AND path=$2",
		b.table,
	)
	var content []byte
	err := b.db.QueryRow(context.Background(), q, b.username, cleanPath).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("postgres GetFileByPath: %w", err)
	}
	return content, nil
}

// PutFile upserts content into the per-user table.
//
// The unique constraint (username, app, profile, label, ext) means this is
// an atomic upsert — if the row already exists, content and updated_at are
// refreshed. The path column is set to the standard filename derived from
// the app/profile/label/ext parameters.
func (b *postgresUserBackend) PutFile(app, profile, label, ext string, content []byte) error {
	if !supportedExtension(ext) {
		return fmt.Errorf("unsupported extension %q", ext)
	}
	// Validate params to prevent SQL injection.
	if !validConfigSegment(app) || !validConfigSegment(profile) || (label != "" && !validConfigSegment(label)) {
		return fmt.Errorf("invalid app/profile/label segment")
	}

	// Derive a standard filename for the path column so GetFileByPath can
	// locate files uploaded via the standard endpoint.
	filename := fmt.Sprintf("%s%s", app, profile)
	if label != "" {
		filename = filename + "-" + label
	}
	filename = filename + ext
	path := fmt.Sprintf("%s/%s", app, filename)

	q := fmt.Sprintf(
		"INSERT INTO %s (username, app, profile, label, ext, content, path, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now()) ON CONFLICT (username, app, profile, label, ext) DO UPDATE SET content = EXCLUDED.content, path = EXCLUDED.path, updated_at = now()",
		b.table,
	)
	_, err := b.db.Exec(context.Background(), q,
		b.username, app, profile, label, ext, string(content), path,
	)
	if err != nil {
		return fmt.Errorf("postgres PutFile: %w", err)
	}
	return nil
}

// PutFileWithFullPath upserts content into the DB and records the relative
// path so it can be served via GetFileByPath.
//
// fullPath is the path stored in the 'path' column, e.g.
// "opt/sonic/configuration/myapp/dev-staging.yaml".
func (b *postgresUserBackend) PutFileWithFullPath(app, profile, label, ext, fullPath string, content []byte) error {
	if !supportedExtension(ext) {
		return fmt.Errorf("unsupported extension %q", ext)
	}
	if !validConfigSegment(app) || !validConfigSegment(profile) || (label != "" && !validConfigSegment(label)) {
		return fmt.Errorf("invalid app/profile/label segment")
	}
	if !IsValidRelativePath(fullPath) {
		return fmt.Errorf("invalid fullPath: %s", fullPath)
	}

	// Derive the lookup key for the unique constraint from the filename.
	filename := extractFilename(fullPath)
	extFromName := filepathExt(filename)
	baseName := strings.TrimSuffix(filename, extFromName)
	parsedApp, parsedProfile, parsedLabel := parseAppProfileLabel(baseName)

	// Use explicit params if provided, otherwise parse from filename.
	lookupApp := app
	lookupProfile := profile
	lookupLabel := label
	if lookupApp == "" {
		lookupApp = parsedApp
	}
	if lookupProfile == "" {
		lookupProfile = parsedProfile
	}
	if lookupLabel == "" {
		lookupLabel = parsedLabel
	}
	if lookupApp == "" || lookupProfile == "" {
		return fmt.Errorf("could not determine app/profile from path: %s", fullPath)
	}

	q := fmt.Sprintf(
		"INSERT INTO %s (username, app, profile, label, ext, content, path, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now()) ON CONFLICT (username, app, profile, label, ext) DO UPDATE SET content = EXCLUDED.content, path = EXCLUDED.path, updated_at = now()",
		b.table,
	)
	_, err := b.db.Exec(context.Background(), q,
		b.username, lookupApp, lookupProfile, lookupLabel, extFromName, string(content), fullPath,
	)
	if err != nil {
		return fmt.Errorf("postgres PutFileWithFullPath: %w", err)
	}
	return nil
}

func (b *postgresUserBackend) ListFiles() ([]Info, error) {
	q := fmt.Sprintf(
		"SELECT app, profile, label, ext, updated_at FROM %s WHERE username=$1 ORDER BY updated_at DESC",
		b.table,
	)
	rows, err := b.db.Query(context.Background(), q, b.username)
	if err != nil {
		return nil, fmt.Errorf("postgres ListFiles: %w", err)
	}
	defer rows.Close()

	var result []Info
	for rows.Next() {
		var info Info
		if err := rows.Scan(&info.App, &info.Profile, &info.Label, &info.Ext, &info.Modified); err != nil {
			return nil, fmt.Errorf("postgres ListFiles scan: %w", err)
		}
		result = append(result, info)
	}
	return result, rows.Err()
}

// DeleteFile removes a config file row from the database.
// Returns ErrNotExist if the row was not found.
func (b *postgresUserBackend) DeleteFile(app, profile, label, ext string) error {
	if !supportedExtension(ext) {
		return fmt.Errorf("unsupported extension %q", ext)
	}
	q := fmt.Sprintf(
		"DELETE FROM %s WHERE username=$1 AND app=$2 AND profile=$3 AND label=$4 AND ext=$5",
		b.table,
	)
	result, err := b.db.Exec(context.Background(), q,
		b.username, app, profile, label, ext,
	)
	if err != nil {
		return fmt.Errorf("postgres DeleteFile: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrNotExist
	}
	return nil
}

// --- helpers ---

// extractFilename returns the last segment of a path.
func extractFilename(p string) string {
	p = strings.ReplaceAll(p, `\`, `/`)
	parts := strings.Split(p, "/")
	return parts[len(parts)-1]
}

// filepathExt returns the file extension (e.g. ".yaml"), lowercased.
func filepathExt(name string) string {
	// Find the last dot in the name.
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return strings.ToLower(name[i:])
		}
	}
	return ""
}

// parseAppProfileLabel splits "myapp-prod-staging" into (app, profile, label).
//
// For raw file serves (GetFileByPath), we treat:
//   - Last hyphen-separated segment as the profile
//   - Everything before as the app
//   - Label is always empty (labels are only used in JSON response path)
//
// This is a simplification since we can't reliably distinguish app/profile/label
// from just the filename. The JSON response path (serveValues) already has this
// information from the URL structure.
func parseAppProfileLabel(base string) (app, profile, label string) {
	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		// 1-2 segments: treat entire string as app, no profile/label
		return base, "", ""
	}
	// 3+ segments: last segment is profile, everything before is app
	return strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1], ""
}

// validConfigSegment validates that a config parameter contains only
// alphanumeric characters, hyphens, underscores, and dots. This prevents
// path traversal attacks and SQL injection.
func validConfigSegment(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// IsValidRelativePath checks that relPath contains only safe characters and
// no path traversal sequences. It allows alphanumeric characters, hyphens,
// underscores, dots, forward slashes, and colons (for Windows drive letters).
func IsValidRelativePath(relPath string) bool {
	if relPath == "" || len(relPath) > 4096 {
		return false
	}
	for _, c := range relPath {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '/' || c == ':') {
			return false
		}
	}
	// Reject .. traversal components.
	if strings.Contains(relPath, "..") {
		return false
	}
	return true
}
