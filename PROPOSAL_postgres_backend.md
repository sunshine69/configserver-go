# Proposal: Add PostgreSQL Backend to Config Server

## 1. Executive Summary

Extend the current Spring Cloud Config Server port (Go) to support **PostgreSQL** as a storage backend, in addition to the existing **filesystem** backend. This enables:

- Centralized configuration storage accessible by multiple config-server instances (horizontal scaling)
- Transactional updates, backups, and point-in-time recovery
- Elimination of filesystem mount dependencies in containerized environments
- Audit trails via database-level tooling

All existing HTTP handlers (`GET /`, `POST /encrypt`, `POST /decrypt`) remain **unified** — the backend is transparent to the client.

---

## 2. Current Architecture (As-Is)

### 2.1 Request Flow

```
Client → Basic Auth → Route Handler → Backend (Filesystem) → Response
```

Three routes exist:
| Route | Purpose |
|---|---|
| `POST /encrypt` | Encrypt a plaintext value with user's key |
| `POST /decrypt` | Decrypt a `{cipher}...` value with user's key |
| `GET /{path}` | Retrieve config — path variants: |
| &nbsp;&nbsp;`/{app}-{profile}[-{label}].{ext}` | Serve raw file bytes |
| &nbsp;&nbsp;`/{app}/{profile}[-{label}]` | Serve as Spring Cloud `GetValuesResponse` (flattened JSON) |
| &nbsp;&nbsp;`/{full-file-path-without-ext}` | Serve raw file by absolute-ish path |

### 2.2 User Configuration (`config.yaml`)

```yaml
server:
  users:
    - username: user1
      directory: /user1/config/dir   # filesystem root
      backend: filesystem            # only option today
      encryption_key: 1qa2ws
```

### 2.3 Limitation of Filesystem Backend

- **Single-point**: Each server instance needs its own disk/NFS mount
- **No horizontal scaling**: Two servers serving the same user must have identical file trees
- **No transactional safety**: Updates to multi-line configs are not atomic on disk
- **No audit**: Requires external tooling to track who changed what

---

## 3. Design Goals

| Goal | Rationale |
|---|---|
| **Backend-agnostic handlers** | Existing handlers must not care whether data came from disk or DB |
| **Backward compatibility** | Existing `config.yaml` with `backend: filesystem` must continue to work without changes |
| **Interface-driven design** | Use a Go `Backend` interface so future backends (Git, S3, Vault) can be added with zero handler changes |
| **Minimal schema footprint** | Store raw file content (TEXT); reuse existing parsers for flattening |
| **Per-user isolation** | Different users can use different backends or different DB tables/schemas |

---

## 4. Proposed Architecture

### 4.1 Backend Interface

```go
type Backend interface {
    // GetFile returns the raw content of a config file.
    // Returns os.ErrNotExist if the file does not exist.
    GetFile(app, profile, label, ext string) ([]byte, error)

    // GetFileByPath returns raw content by an absolute-style path.
    // Returns os.ErrNotExist if the file does not exist.
    GetFileByPath(fullPath string) ([]byte, error)

    // ListFiles returns all available config files for a user (optional,
    // useful for discovery/admin endpoints).
    ListFiles() ([]FileInfo, error)
}

type FileInfo struct {
    App      string
    Profile  string
    Label    string
    Ext      string
    Path     string // canonical path identifier
    Modified time.Time
}
```

Both `filesystemBackend` and `postgresBackend` implement this interface. Handlers accept `Backend` and never touch disk or DB directly.

### 4.2 Database Schema

```sql
CREATE TABLE IF NOT EXISTS config_files (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(128) NOT NULL,          -- which config-server user owns this
    app         VARCHAR(256) NOT NULL,
    profile     VARCHAR(256) NOT NULL,
    label       VARCHAR(256) NOT NULL DEFAULT '',
    ext         VARCHAR(16) NOT NULL,           -- .json, .yaml, .yml, .properties
    content     TEXT NOT NULL,                  -- raw file content
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (username, app, profile, label, ext)
);

-- Fast lookups by the composite keys the handlers query
CREATE INDEX idx_config_files_lookup
    ON config_files (username, app, profile, label, ext);

-- Optional: full-text search for admin UI
-- CREATE INDEX idx_config_files_content ON config_files
--     USING gin(to_tsvector('english', content));
```

#### Why store raw content (not flattened)?

- **Format fidelity**: YAML, JSON, and properties all have subtle parsing semantics; storing raw avoids losing anything
- **Reuse existing logic**: The current `parseConfigData()` and `FlatternDataToMap()` functions work on `[]byte` — they can read from DB the same way they read from disk
- **Encryption transparency**: `{cipher}` patterns live in the raw text; decryption happens at read time, not storage time
- **Single source of truth**: No need to maintain parallel raw + flattened stores

#### Alternative considered and rejected: Key-Value store

| Approach | Pros | Cons |
|---|---|---|
| **Raw content** (chosen) | Format-agnostic, single store, preserves `{cipher}` | Client still pays for parse cost |
| Flattened KV store | Faster reads for Spring Boot clients | Loses format nuances, two stores to maintain, cipher handling is awkward |
| BLOB/bytea | Handles binary files | Overkill; TEXT is fine for config files < few MB |

### 4.3 Configuration Changes

Add a `postgres` section to `BackendConfigMap` and extend `UserConfig`:

```yaml
server:
  users:
    - username: user1
      directory: /user1/config/dir       # kept for filesystem users
      backend: postgres                   # new: "filesystem" | "git" | "postgres"
      encryption_key: 1qa2ws
      # New fields (only relevant when backend=postgres):
      postgres:
        connection_string: "postgres://config:pass@db-host:5432/configdb?sslmode=disable"
        table_name: "config_files"        # optional, defaults to "config_files"

backend_config:
  filesystem:
    directories:
      - /user1/config/dir
  postgres:
    # Optional global fallback connection string if user-level is not set
    default_connection_string: "postgres://config:pass@db-host:5432/configdb?sslmode=disable"
```

### 4.4 New Types

```go
type PostgresUserConfig struct {
    ConnectionString string `yaml:"connection_string"`
    TableName        string `yaml:"table_name"`
}

type PostgresBackendConfig struct {
    DefaultConnectionString string             `yaml:"default_connection_string"`
    Users                   map[string]PostgresUserConfig `yaml:"users"` // optional overrides
}

type BackendConfigMap struct {
    FileSystem FileSystemConfig        `yaml:"filesystem"`
    Git        GitConfig               `yaml:"git"`
    Postgres   PostgresBackendConfig   `yaml:"postgres"`
}

type UserConfig struct {
    // ... existing fields ...
    Backend       string              `yaml:"backend"`
    Postgres      PostgresUserConfig  `yaml:"postgres"` // new
}
```

### 4.5 Backend Resolver

A new `BackendResolver` maps a user to their `Backend` implementation:

```go
type BackendResolver struct {
    fsBackend    *FileSystemBackend
    pgBackend    *postgresBackend
    pgConfig     map[string]PostgresUserConfig
    globalPgConn string
}

func (r *BackendResolver) ForUser(user *UserConfig) (Backend, error) {
    switch user.Backend {
    case "filesystem":
        return r.fsBackend, nil
    case "postgres":
        return r.pgBackend.ForUser(user)
    default:
        return nil, fmt.Errorf("unsupported backend: %s", user.Backend)
    }
}
```

The resolver is built at startup from `config.yaml`. The `postgresBackend` pool lazily opens `*sql.DB` connections (cached per connection string).

---

## 5. Handler Modifications

### 5.1 Refactored Handler Signature

```go
// Before:
func getValuesHandler(w http.ResponseWriter, r *http.Request) {
    user := users[r.Header.Get("X-Username")]
    // directly calls serveFile() which reads from os
}

// After:
type HandlerDeps struct {
    Users     map[string]*UserConfig
    Backend   *BackendResolver
}

func (h *HandlerDeps) getValuesHandler(w http.ResponseWriter, r *http.Request) {
    user := h.Users[r.Header.Get("X-Username")]
    be, err := h.Backend.ForUser(user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    // ... routing logic uses be.GetFile() or be.GetFileByPath() instead of os functions
}
```

### 5.2 serveFile Refactor

```go
func serveFile(w http.ResponseWriter, user *UserConfig, be Backend, filename string) error {
    data, err := be.GetFileByPath(filename)
    if errors.Is(err, fs.ErrNotExist) {
        http.Error(w, "File not found", http.StatusNotFound)
        return err
    }
    if err != nil {
        http.Error(w, "Error reading config", http.StatusInternalServerError)
        return err
    }
    w.Write(data)
    return nil
}
```

### 5.3 serveValues Refactor

```go
func serveValues(w http.ResponseWriter, user *UserConfig, be Backend, app, profile, label string) error {
    responseObj := GetValuesResponse{
        Name:     app,
        Profiles: []string{profile},
        Label:    u.Ternary(label != "", &label, nil),
    }

    for _, ext := range supportedConfigFileType {
        data, err := be.GetFile(app, profile, label, ext)
        if errors.Is(err, fs.ErrNotExist) {
            continue
        }
        if err != nil {
            log.Printf("[WARN] backend error for %s-%s-%s.%s: %v", app, profile, label, ext, err)
            continue
        }
        data = processCipherPatterns(string(data), user)
        result := parseConfigData(data, ext)
        responseObj.PropertySources = append(responseObj.PropertySources, PropertySource{
            Name:   fmt.Sprintf("postgres:config_files where app=%s profile=%s", app, profile),
            Source: result,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    return json.NewEncoder(w).Encode(responseObj)
}
```

---

## 6. PostgreSQL Backend Implementation

```go
package backend

import (
    "database/sql"
    "errors"
    "fmt"
    "os"
    "sync"
    "time"
)

// postgresBackend manages DB connections for all postgres-backed users.
type postgresBackend struct {
    mu       sync.RWMutex
    pools    map[string]*sql.DB  // keyed by connection_string
    users    map[string]PostgresUserConfig
    globalDSN string
}

func NewPostgresBackend(globalDSN string, userConfigs map[string]PostgresUserConfig) *postgresBackend {
    return &postgresBackend{
        pools:     make(map[string]*sql.DB),
        users:     userConfigs,
        globalDSN: globalDSN,
    }
}

// ForUser returns a Backend scoped to a specific user's table/connection.
func (b *postgresBackend) ForUser(user *UserConfig) (Backend, error) {
    dsn := b.globalDSN
    if pc, ok := b.users[user.Username]; ok && pc.ConnectionString != "" {
        dsn = pc.ConnectionString
    }
    pool, err := b.getPool(dsn)
    if err != nil {
        return nil, err
    }
    tableName := "config_files"
    if pc, ok := b.users[user.Username]; ok && pc.TableName != "" {
        tableName = pc.TableName
    }
    return &postgresUserBackend{db: pool, table: tableName, user: user.Username}, nil
}

func (b *postgresBackend) getPool(dsn string) (*sql.DB, error) {
    b.mu.RLock()
    if pool, ok := b.pools[dsn]; ok {
        b.mu.RUnlock()
        return pool, nil
    }
    b.mu.RUnlock()

    b.mu.Lock()
    defer b.mu.Unlock()
    // Double-check after acquiring write lock
    if pool, ok := b.pools[dsn]; ok {
        return pool, nil
    }
    pool, err := sql.Open("pgx", dsn) // or "lib/pq"
    if err != nil {
        return nil, fmt.Errorf("open postgres: %w", err)
    }
    pool.SetMaxOpenConns(10)
    pool.SetMaxIdleConns(5)
    pool.SetConnMaxLifetime(5 * time.Minute)
    if err := pool.Ping(); err != nil {
        return nil, fmt.Errorf("ping postgres: %w", err)
    }
    b.pools[dsn] = pool
    return pool, nil
}

// postgresUserBackend is bound to one user's table in one DB connection.
type postgresUserBackend struct {
    db      *sql.DB
    table   string
    user    string
}

func (b *postgresUserBackend) GetFile(app, profile, label, ext string) ([]byte, error) {
    row := b.db.QueryRow(
        fmt.Sprintf("SELECT content FROM %s WHERE username=$1 AND app=$2 AND profile=$3 AND label=$4 AND ext=$5", b.table),
        b.user, app, profile, label, ext,
    )
    var content []byte
    err := row.Scan(&content)
    if errors.Is(err, sql.ErrNoRows) {
        return nil, os.ErrNotExist
    }
    if err != nil {
        return nil, err
    }
    return content, nil
}

func (b *postgresUserBackend) GetFileByPath(fullPath string) ([]byte, error) {
    // Parse the path back into (app, profile, label, ext) components.
    // Format: "{app}-{profile}[-{label}].{ext}" or full path segments.
    // ... implementation mirrors filesystem path parsing ...
}

func (b *postgresUserBackend) ListFiles() ([]FileInfo, error) {
    rows, err := b.db.Query(
        fmt.Sprintf("SELECT app, profile, label, ext, updated_at FROM %s WHERE username=$1 ORDER BY updated_at DESC", b.table),
        b.user,
    )
    // ... map rows to []FileInfo ...
}
```

---

## 7. Path Parsing for DB Lookups

The critical mapping challenge: translating URL paths into `(app, profile, label, ext)` tuples.

### 7.1 Current Path Variants

| URL Path | Parsed As |
|---|---|
| `/app1-prod.json` | file = `app1-prod.json` |
| `/app1-prod/` | app=app1, profile=prod, label="" |
| `/app1-prod-staging/` | app=app1, profile=prod, label="staging" |
| `/app1-prod/label1` | app=app1, profile=prod, label="label1" |
| `/app1-prod/label1/file.json` | raw file by path |

### 7.2 DB Lookup Strategy

For `GetFile(app, profile, label, ext)`:

```
{app}-{profile}[-{label}].{ext}
```

The parser must handle the ambiguity where `app` and `profile` are separated by a hyphen. The current code already handles this by iterating extensions and checking file existence. For DB, we replicate that logic:

```go
func (b *postgresUserBackend) GetFile(app, profile, label, ext string) ([]byte, error) {
    // This is the primary codepath from serveValues() which already
    // has parsed app, profile, label from the URL segments.
    // ext comes from the supportedConfigFileType loop.
    ...
}
```

For `GetFileByPath(filename)` (serving raw files):

```go
// Parse "app1-prod-staging.json" → app="app1", profile="prod", label="staging", ext=".json"
// Parse "/full/path/to/app1-prod.json" → extract the filename, then same as above
```

This is the same parsing logic already in `serveValues()` — it just needs to query the DB instead of checking `os.Exists()`.

### 7.3 Handling the App/Profile Ambiguity

In Spring Cloud Config, `app` and `profile` are joined by a **single hyphen** in the filename: `myapp-prod.yaml`. The first hyphen is the delimiter. This is preserved in DB lookups:

```sql
-- Given: app="myapp", profile="prod", label="", ext=".yaml"
-- Stored as row: (username, 'myapp', 'prod', '', '.yaml')

-- Given: app="myapp", profile="prod", label="staging", ext=".yaml"
-- Stored as row: (username, 'myapp', 'prod', 'staging', '.yaml')
```

URL `/myapp-prod-staging.yaml` → split on last two hyphens using extension knowledge.

---

## 8. Initialization & Data Migration

### 8.1 Schema Migration

Add a `migrate` subcommand or startup flag:

```go
// In main(), if --migrate flag is set:
if migrate {
    runMigrations(db)
}

func runMigrations(db *sql.DB) {
    _, err := db.Exec(`
        CREATE TABLE IF NOT EXISTS config_files ( ... );
        CREATE INDEX IF NOT EXISTS idx_config_files_lookup
            ON config_files (username, app, profile, label, ext);
    `)
}
```

### 8.2 Import from Filesystem (One-Time Migration)

```bash
# New CLI command to seed the DB from an existing filesystem backend
configservergo import --from /user1/config/dir --user user1 --backend postgres \
    --dsn "postgres://..."
```

This walks the directory tree, reads each config file, and `INSERT ... ON CONFLICT (username, app, profile, label, ext) DO UPDATE SET content = $1, updated_at = now()` into the DB.

### 8.3 Live Sync (Optional, Future)

Not in v1 scope. Could be added later: watch filesystem changes and sync to DB. For now, migration is one-time.

---

## 9. Filesystem + Postgres Coexistence

A user can have their config served from **either** backend, chosen per-user in `config.yaml`. This proposal does **not** mix both for a single user in v1 — it's an either/or choice.

Rationale: mixing creates ambiguity (which source wins on conflict?), complicates the handler routing, and adds no immediate value. Users can migrate gradually:

```
Phase 1: All users on filesystem
Phase 2: Migrate power user A to postgres (one at a time)
Phase 3: Migrate remaining users
Phase 4: Deprecate filesystem backend
```

---

## 10. Caching Strategy

PostgreSQL lookups are fast, but for high-throughput scenarios, an in-memory cache layer is recommended:

```go
type cachingBackend struct {
    inner   Backend
    cache   *lru.Cache[string, cachedEntry]
    ttl     time.Duration
}

type cachedEntry struct {
    content  []byte
    expired  time.Time
}
```

- **v1 scope**: No caching. Keep it simple. DB queries for config files are expected to be < 2ms with the composite index.
- **v2**: Add optional LRU cache with configurable TTL. Cache key = `username:app:profile:label:ext`.
- **Invalidation**: On `POST /encrypt`/`/decrypt`, invalidate related cache entries (or just use short TTL like 30s).

---

## 11. Security Considerations

| Concern | Mitigation |
|---|---|
| **DSN in config.yaml** | Supports `postgresql://` DSN which can embed credentials. Recommend using K8s Secrets / env vars to inject DSN at deploy time rather than hardcoding |
| **SQL Injection** | All queries use parameterized `$1, $2...` placeholders — no string concatenation for values |
| **Table name injection** | `table_name` is user-configurable but should be validated against an allowlist or regex `^[a-zA-Z_][a-zA-Z0-9_]*$` |
| **Connection pooling** | Limit `MaxOpenConns` per pool to prevent DB overload from many users |
| **SSL/TLS to DB** | DSN supports `sslmode=require` or `sslmode=verify-full` — documented but not enforced in v1 |
| **Cipher data in DB** | `{cipher}` data is stored encrypted at rest in the DB just like on disk. No additional encryption needed at the column level unless compliance requires it |

---

## 12. Dependencies

Add one new Go dependency:

```
github.com/jackc/pgx/v5   (pgx v5)   — modern, fast, feature-rich PostgreSQL driver
```

Alternative: `github.com/lib/pq` (older, battle-tested but slower).

`pgx v5` is recommended for:
- Native support for `pgx.Pool` (connection pooling built-in)
- Better error handling
- Active maintenance

---

## 13. Implementation Plan (Step-by-Step)

### Phase 1: Core Infrastructure (2-3 days)

| Step | Task | Files |
|---|---|---|
| 1.1 | Add `pgx/v5` dependency | `go.mod` |
| 1.2 | Define `Backend` interface + `FileInfo` struct | `backend/interface.go` (new) |
| 1.3 | Refactor `FileSystemBackend` to implement interface | `backend/filesystem.go` (new) |
| 1.4 | Add `PostgresBackendConfig`, `PostgresUserConfig` types | `main.go` |
| 1.5 | Add `postgres` section parsing to `LoadConfig()` | `main.go` |
| 1.6 | Implement `postgresBackend.GetFile()` | `backend/postgres.go` (new) |
| 1.7 | Implement `postgresBackend.GetFileByPath()` | `backend/postgres.go` (new) |
| 1.8 | Implement `postgresBackend.ListFiles()` | `backend/postgres.go` (new) |
| 1.9 | Build `BackendResolver` | `backend/resolver.go` (new) |

### Phase 2: Handler Refactoring (1-2 days)

| Step | Task |
|---|---|
| 2.1 | Refactor `getValuesHandler` to accept and use `Backend` |
| 2.2 | Refactor `serveFile` to use `Backend.GetFileByPath()` |
| 2.3 | Refactor `serveValues` to use `Backend.GetFile()` |
| 2.4 | Wire `BackendResolver` into `main()` startup |
| 2.5 | Add `--migrate` flag for schema creation |

### Phase 3: Testing & Migration (1-2 days)

| Step | Task |
|---|---|
| 3.1 | Integration tests: spin up test Postgres (testcontainers or docker), run full handler flow |
| 3.2 | Write `import` CLI command for filesystem → DB migration |
| 3.3 | End-to-end test: filesystem user (existing) + postgres user (new) in same config.yaml |
| 3.4 | Performance test: compare response times filesystem vs postgres with 100 concurrent requests |

### Phase 4: Polish (1 day)

| Step | Task |
|---|---|
| 4.1 | Documentation: update `config.yaml` examples, README |
| 4.2 | Add SQL migration file as standalone `.sql` for manual DBA use |
| 4.3 | Consider adding health check endpoint `GET /health` that pings DB |
| 4.4 | Add graceful DB connection shutdown in `main()` |

**Total estimated effort: 5-8 days**

---

## 14. Testing Strategy

### 4.1 Unit Tests

| Test | Description |
|---|---|
| `TestPostgresBackend_GetFile` | Insert a row, query it back, verify content matches |
| `TestPostgresBackend_GetFile_NotFound` | Query non-existent row, verify `os.ErrNotExist` returned |
| `TestPostgresBackend_GetFileByPath` | Parse paths like `myapp-prod.yaml`, `myapp-prod-staging.json` |
| `TestBackendResolver_Filesystem` | User with `backend: filesystem` gets filesystem backend |
| `TestBackendResolver_Postgres` | User with `backend: postgres` gets postgres backend |
| `TestBackendResolver_UnknownBackend` | User with unsupported backend returns error |
| `TestPostgresBackend_MultipleUsers` | Two users with different DSNs get separate connection pools |

### 4.2 Integration Tests

Use `testcontainers-go` for ephemeral Postgres:

```go
func TestIntegration_PostgresFullFlow(t *testing.T) {
    container := testcontainers.PostgresContainer(...)
    defer container.Terminate(ctx)

    // 1. Seed: INSERT config file into DB
    // 2. Start HTTP server with postgres backend
    // 3. GET /myapp-prod → verify 200 + correct flattened JSON
    // 4. GET /myapp-prod-staging.json → verify 200 + raw content
    // 5. GET /nonexistent → verify 404
    // 6. POST /encrypt → verify encryption still works
    // 7. POST /decrypt → verify decryption still works
}
```

### 4.3 Backward Compatibility Tests

| Scenario | Expected |
|---|---|
| config.yaml has only `backend: filesystem` | Everything works exactly as before |
| config.yaml has mix of filesystem and postgres users | Each user's requests route to correct backend |
| Postgres user has no files in DB | Returns same 404/error as filesystem missing file |

---

## 15. Future Enhancements (Out of Scope for v1)

| Feature | Description |
|---|---|
| **Git backend** | Already declared in config (`GitConfig`), now actually implemented |
| **Multi-backend fallback** | Try DB first, fall back to filesystem on miss |
| **Config write-back API** | `PUT /{app}/{profile}/{label}` to update config in DB (currently read-only) |
| **Audit log** | Track who changed what config and when |
| **Label-based branching** | Full Spring Cloud Config label semantics (git branches) |
| **Encryption at rest** | Column-level encryption for `content` field using user's `encryption_key` |
| **Cache layer** | LRU cache with configurable TTL |
| **Admin API** | `GET /admin/config-files` to list all stored configs across users |
| **Eventual consistency** | Pub/sub to invalidate caches across multiple config-server instances |

---

## 16. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Path parsing ambiguity between app/profile in DB lookups | Medium | High | Thorough unit tests on path parsing; same logic as current filesystem code |
| pgx driver compatibility issues with existing code patterns | Low | Medium | pgx is well-documented; fallback to lib/pq if needed |
| Breaking existing filesystem handler behavior during refactor | Medium | High | Comprehensive integration tests before merge; keep filesystem as default |
| DB connection pool exhaustion under load | Low | High | Set MaxOpenConns per pool; add connection health checks |
| Schema migration fails on existing deployments | Low | Medium | `CREATE TABLE IF NOT EXISTS` is idempotent; add migration versioning table for future |

---

## 17. Decision Log

| Decision | Choice | Rationale |
|---|---|---|
| Raw content vs flattened KV in DB | **Raw content** | Preserves format fidelity; reuses existing parsers |
| Per-user DSN vs global DSN | **Per-user with global fallback** | Flexibility for multi-tenant; simplicity for single-tenant |
| pgx vs lib/pq | **pgx/v5** | Modern, fast, built-in pooling, active maintenance |
| Backend as interface vs switch/if-else | **Interface** | Clean extensibility; future Git/S3 backends cost nothing to add |
| Mixing backends per user | **Either/or** | Simpler v1; mixing adds conflict-resolution complexity |
| Caching in v1 | **No caching** | Keep scope tight; DB is fast with proper indexes |
| Schema migration approach | **CREATE IF NOT EXISTS at startup** | Zero-op for existing DBs; safe for repeated runs |

---

## Appendix A: Example config.yaml with Postgres User

```yaml
server:
  port: 7777
  ssl:
    enable: false
  users:
    # Existing filesystem user (unchanged behavior)
    - username: user1
      password: 123
      encryption_key: 1qa2ws
      directory: /user1/config/dir
      backend: filesystem

    # New postgres user
    - username: user2
      password: secure_password
      encryption_key: mySecretKey
      backend: postgres
      postgres:
        connection_string: "postgres://config_user:secret@db.internal:5432/configdb?sslmode=verify-full"
        table_name: "config_files"

backend_config:
  filesystem:
    directories:
      - /user1/config/dir
  postgres:
    default_connection_string: "postgres://config_user:secret@db.internal:5432/configdb?sslmode=verify-full"
```

## Appendix B: Example SQL Migration

```sql
-- migrations/001_create_config_files.sql

BEGIN;

CREATE TABLE IF NOT EXISTS config_files (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(128) NOT NULL,
    app         VARCHAR(256) NOT NULL,
    profile     VARCHAR(256) NOT NULL,
    label       VARCHAR(256) NOT NULL DEFAULT '',
    ext         VARCHAR(16) NOT NULL,
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (username, app, profile, label, ext)
);

CREATE INDEX IF NOT EXISTS idx_config_files_lookup
    ON config_files (username, app, profile, label, ext);

-- Track migrations
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO schema_migrations (version) VALUES (1)
ON CONFLICT (version) DO NOTHING;

COMMIT;
```

## Appendix C: Example Seed Data

```sql
-- Seed a config for user2
INSERT INTO config_files (username, app, profile, label, ext, content)
VALUES (
    'user2',
    'myapp',
    'production',
    '',
    '.yaml',
    E"spring:\n  datasource:\n    url: jdbc:postgresql://db:5432/mydb\n    password: '{cipher}AES/ECB/PKCS5Padding/Base64:...'\n  redis:\n    host: redis.internal\n    port: 6379"
)
ON CONFLICT (username, app, profile, label, ext)
DO UPDATE SET content = EXCLUDED.content, updated_at = now();
```
