package backend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FileSystemBackend serves config files from a directory on disk.
//
// It wraps the existing filesystem logic from main.go into the Backend
// interface so handlers can swap between filesystem and postgres without
// changes.
type FileSystemBackend struct {
	// BaseDir is the root directory for this backend instance.
	// Users with backend=filesystem mount their own BaseDir.
	BaseDir string
}

// NewFileSystemBackend creates a new filesystem backend rooted at baseDir.
func NewFileSystemBackend(baseDir string) *FileSystemBackend {
	return &FileSystemBackend{BaseDir: baseDir}
}

// GetFile resolves a config file from the filesystem using the Spring Cloud Config
// hierarchical naming convention. The filename is built as:
//
//	{app}[-{profile}][-{label}].{ext}
//
// Empty profile or label segments are omitted (no trailing hyphens). For example:
//
//	GetFile("foo", "dev", "main", ".yaml")  → foo-dev-main.yaml
//	GetFile("foo", "dev", "", ".yaml")      → foo-dev.yaml
//	GetFile("foo", "", "main", ".yaml")     → foo-main.yaml
//	GetFile("foo", "", "", ".yaml")         → foo.yaml
func (b *FileSystemBackend) GetFile(app, profile, label string, ext string) ([]byte, error) {
	filenameWithoutExt := BuildConfigFilename(app, profile, label)
	fullPath := filepath.Join(b.BaseDir, filenameWithoutExt+ext)
	return b.readFile(fullPath)
}

// BuildConfigFilename constructs a config filename without extension using the
// Spring Cloud Config hierarchical naming convention: {app}[-{profile}][-{label}].
// Empty profile or label segments are omitted to avoid trailing hyphens.
func BuildConfigFilename(app, profile, label string) string {
	var parts []string
	parts = append(parts, app)
	if profile != "" {
		parts = append(parts, profile)
	}
	if label != "" {
		parts = append(parts, label)
	}
	return strings.Join(parts, "-")
}

func (b *FileSystemBackend) GetFileByPath(filename string) ([]byte, error) {
	// Prepend base directory to create full path.
	fullPath := filepath.Join(b.BaseDir, filename)
	if !strings.Contains(fullPath, b.BaseDir) {
		return nil, fmt.Errorf("path outside base directory: %s", fullPath)
	}
	return b.readFile(fullPath)
}

func (b *FileSystemBackend) readFile(fullPath string) ([]byte, error) {
	if _, err := os.Stat(fullPath); errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotExist
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fullPath, err)
	}
	return data, nil
}

// PutFile writes content to disk at the resolved path:
//
//	{BaseDir}/{app}-{profile}[-{label}].{ext}
//
// Returns an error when the extension is not in the supported list, when
// the resolved path escapes the base directory, or when the write fails.
// Existing files are overwritten (upsert).
func (b *FileSystemBackend) PutFile(app, profile, label, ext string, content []byte) error {
	if !supportedExtension(ext) {
		return fmt.Errorf("unsupported extension %q", ext)
	}
	filenameWithoutExt := BuildConfigFilename(app, profile, label)
	fullPath := filepath.Join(b.BaseDir, filenameWithoutExt+ext)

	// Resolve to absolute to check for directory traversal.
	abs, err := filepath.Abs(fullPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	baseAbs, err := filepath.Abs(b.BaseDir)
	if err != nil {
		return fmt.Errorf("resolve base dir: %w", err)
	}
	if !strings.HasPrefix(abs, baseAbs+string(filepath.Separator)) && abs != baseAbs {
		return fmt.Errorf("path escapes base directory: %s", fullPath)
	}

	// Ensure the directory exists.
	if dir := filepath.Dir(abs); dir != b.BaseDir {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
	}
	if err := os.WriteFile(abs, content, 0o644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

// PutFileWithFullPath writes content to disk at the given relative path.
// The path is resolved relative to the backend's BaseDir, and is validated
// to prevent directory traversal.
//
// If fullPath is empty, the behavior is identical to PutFile.
func (b *FileSystemBackend) PutFileWithFullPath(app, profile, label, ext, fullPath string, content []byte) error {
	if !supportedExtension(ext) {
		return fmt.Errorf("unsupported extension %q", ext)
	}

	var destPath string
	if fullPath != "" {
		destPath = filepath.Join(b.BaseDir, fullPath)
	} else {
		// Fall back to standard naming convention
		filenameWithoutExt := BuildConfigFilename(app, profile, label)
		destPath = filepath.Join(b.BaseDir, filenameWithoutExt+ext)
	}

	// Resolve to absolute to check for directory traversal.
	abs, err := filepath.Abs(destPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	baseAbs, err := filepath.Abs(b.BaseDir)
	if err != nil {
		return fmt.Errorf("resolve base dir: %w", err)
	}
	if !strings.HasPrefix(abs, baseAbs+string(filepath.Separator)) && abs != baseAbs {
		return fmt.Errorf("path escapes base directory: %s", destPath)
	}

	// Ensure the directory exists.
	if dir := filepath.Dir(abs); dir != b.BaseDir {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
	}
	if err := os.WriteFile(abs, content, 0o644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

func supportedExtension(ext string) bool {
	for _, e := range []string{".json", ".yaml", ".yml", ".properties"} {
		if ext == e {
			return true
		}
	}
	return false
}

// DeleteFile removes the config file at the given address from disk.
// Returns ErrNotExist if the file was not found.
func (b *FileSystemBackend) DeleteFile(app, profile, label, ext string) error {
	if !supportedExtension(ext) {
		return fmt.Errorf("unsupported extension %q", ext)
	}
	filenameWithoutExt := BuildConfigFilename(app, profile, label)
	fullPath := filepath.Join(b.BaseDir, filenameWithoutExt+ext)

	// Resolve to absolute to check for directory traversal.
	abs, err := filepath.Abs(fullPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	baseAbs, err := filepath.Abs(b.BaseDir)
	if err != nil {
		return fmt.Errorf("resolve base dir: %w", err)
	}
	if !strings.HasPrefix(abs, baseAbs+string(filepath.Separator)) && abs != baseAbs {
		return fmt.Errorf("path escapes base directory: %s", fullPath)
	}

	if err := os.Remove(abs); err != nil {
		if os.IsNotExist(err) {
			return ErrNotExist
		}
		return fmt.Errorf("delete file: %w", err)
	}
	return nil
}

func (b *FileSystemBackend) ListFiles() ([]Info, error) {
	var files []Info
	err := filepath.Walk(b.BaseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".properties" {
			rel, _ := filepath.Rel(b.BaseDir, path)
			files = append(files, Info{
				App:      rel,
				Modified: info.ModTime(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
