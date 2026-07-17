package backend

import (
	"errors"
	"os"
	"time"
)

// ErrNotExist is the sentinel error returned when a file does not exist in
// the backend. Handlers check for this to produce 404s.
var ErrNotExist = os.ErrNotExist

// Info holds metadata about a stored config file.
type Info struct {
	App      string
	Profile  string
	Label    string
	Ext      string
	Modified time.Time
}

// Backend is the contract every storage backend must satisfy.
//
// Handlers never touch the filesystem or database directly — they call these
// methods and the backend decides where the bytes come from.
type Backend interface {
	// GetFile returns raw config-file content.
	//
	// Parameters are the parsed URL components (app, profile, label, ext).
	// Ext must be one of the supported extensions (.json, .yaml, .yml, .properties).
	//
	// Returns ErrNotExist when the file is not found so handlers can fall
	// through to try the next extension or return a 404.
	GetFile(app, profile, label string, ext string) ([]byte, error)

	// GetFileByPath returns raw content addressed by a full path or filename.
	// Used when the caller requests a raw file serve (not the Spring Cloud
	// GetValues format).
	GetFileByPath(fullPath string) ([]byte, error)

	// ListFiles returns all config files known to this backend for this user.
	// Not currently used by handlers — reserved for future admin endpoints.
	ListFiles() ([]Info, error)

	// PutFile stores config-file content at the given address (app,
	// profile, label, ext). Ext is already validated as one of the supported
	// extensions. Callers are responsible for sanitising app/profile/label
	// (no path separators). Returns ErrUnsupportedExtension when ext is
	// invalid.
	PutFile(app, profile, label, ext string, content []byte) error

	// PutFileWithFullPath stores content and records a relative path for
	// retrieval via GetFileByPath. The path is stored in the backend and
	// used when CONFIGSERVER_FILEPATH is enabled.
	// If fullPath is empty, the behavior is identical to PutFile.
	PutFileWithFullPath(app, profile, label, ext, fullPath string, content []byte) error

	// DeleteFile removes the config file at the given address.
	// Returns ErrNotExist if the file was not found.
	DeleteFile(app, profile, label, ext string) error
}

// IsNotExist reports whether err is a "not found" error from any backend.
func IsNotExist(err error) bool {
	return errors.Is(err, ErrNotExist)
}
