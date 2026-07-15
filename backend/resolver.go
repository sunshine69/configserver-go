package backend

import "fmt"

// UserBackend is satisfied by *UserConfig from main.go.
//
// We use an interface instead of importing main.go's types to avoid circular
// dependencies. Both UserConfig and PostgresUserConfig fields we need are
// small and obvious — the interface is self-documenting.
type UserBackend interface {
	GetUsername() string
	GetBackend() string
	GetPostgresDSN() string
	GetPostgresTable() string
}

// Resolver maps a user to their appropriate Backend implementation.
//
// It holds references to all configured backends (filesystem, postgres) and
// selects the right one based on the user's `Backend` field.
type Resolver struct {
	fsBackend *FileSystemBackend
	pgBackend *PostgresBackend
}

// NewResolver creates a Resolver with the given backends.
//
// Both fs and pg can be nil — if a user references a backend that wasn't
// configured, ForUser returns an error.
func NewResolver(fs *FileSystemBackend, pg *PostgresBackend) *Resolver {
	return &Resolver{
		fsBackend: fs,
		pgBackend: pg,
	}
}

// ForUser returns the Backend for the given user, or an error if the user's
// backend is not configured or the backend type is unknown.
func (r *Resolver) ForUser(user UserBackend) (Backend, error) {
	switch user.GetBackend() {
	case "filesystem", "file":
		if r.fsBackend == nil {
			return nil, fmt.Errorf("filesystem backend not configured")
		}
		return r.fsBackend, nil
	case "postgres", "postgresql", "db":
		if r.pgBackend == nil {
			return nil, fmt.Errorf("postgres backend not configured")
		}
		return r.pgBackend.ForUser(user)
	default:
		return nil, fmt.Errorf("unsupported backend '%s'", user.GetBackend())
	}
}
