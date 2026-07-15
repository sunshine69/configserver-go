package backend

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAppProfileLabel(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		wantApp  string
		wantProf string
		wantLbl  string
	}{
		{"simple app-profile", "myapp-prod", "myapp-prod", "", ""},
		{"app-profile-label", "myapp-prod-staging", "myapp-prod", "staging", ""},
		{"single part", "myapp", "myapp", "", ""},
		{"three-part with label", "my-cool-app-production-staging", "my-cool-app-production", "staging", ""},
		{"four-part", "myapp-prod-staging-v2", "myapp-prod-staging", "v2", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, profile, label := parseAppProfileLabel(tt.base)
			if app != tt.wantApp {
				t.Errorf("app = %q, want %q", app, tt.wantApp)
			}
			if profile != tt.wantProf {
				t.Errorf("profile = %q, want %q", profile, tt.wantProf)
			}
			if label != tt.wantLbl {
				t.Errorf("label = %q, want %q", label, tt.wantLbl)
			}
		})
	}
}

func TestExtractFilename(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple filename", "myapp-prod.yaml", "myapp-prod.yaml"},
		{"full path", "/home/user/config/myapp-prod.yaml", "myapp-prod.yaml"},
		{"windows path", `C:\Users\config\myapp-prod.yaml`, "myapp-prod.yaml"},
		{"nested path", "/a/b/c/d/e/file.json", "file.json"},
		{"path with backslashes", `C:\Users\config\subdir\file.yaml`, "file.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFilename(tt.input)
			if got != tt.expected {
				t.Errorf("extractFilename(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFilepathExt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"yaml", "myapp.yaml", ".yaml"},
		{"yml", "myapp.yml", ".yml"},
		{"json", "myapp.json", ".json"},
		{"properties", "myapp.properties", ".properties"},
		{"no extension", "myapp", ""},
		{"case insensitive", "MYAPP.YAML", ".yaml"},
		{"multiple dots", "my.app.yaml", ".yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filepathExt(tt.input)
			if got != tt.expected {
				t.Errorf("filepathExt(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestFileSystemBackend_GetFile(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create a test config file
	testContent := []byte("spring:\n  datasource:\n    url: jdbc:postgresql://db/mydb\n")
	err := os.WriteFile(filepath.Join(tmpDir, "myapp-prod.yaml"), testContent, 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	backend := NewFileSystemBackend(tmpDir)

	// Test successful retrieval
	content, err := backend.GetFile("myapp", "prod", "", ".yaml")
	if err != nil {
		t.Fatalf("GetFile returned error: %v", err)
	}
	if string(content) != string(testContent) {
		t.Errorf("content mismatch: got %q, want %q", string(content), string(testContent))
	}

	// Test file not found
	_, err = backend.GetFile("nonexistent", "prod", "", ".yaml")
	if !IsNotExist(err) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}

	// Test label
	err = os.WriteFile(filepath.Join(tmpDir, "myapp-prod-staging.yaml"), testContent, 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	content, err = backend.GetFile("myapp", "prod", "staging", ".yaml")
	if err != nil {
		t.Fatalf("GetFile with label returned error: %v", err)
	}
	if string(content) != string(testContent) {
		t.Errorf("content mismatch with label: got %q, want %q", string(content), string(testContent))
	}
}

func TestFileSystemBackend_GetFileByPath(t *testing.T) {
	tmpDir := t.TempDir()

	testContent := []byte("key: value")
	err := os.WriteFile(filepath.Join(tmpDir, "test.yaml"), testContent, 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	backend := NewFileSystemBackend(tmpDir)

	// Test successful retrieval
	content, err := backend.GetFileByPath("test.yaml")
	if err != nil {
		t.Fatalf("GetFileByPath returned error: %v", err)
	}
	if string(content) != string(testContent) {
		t.Errorf("content mismatch: got %q, want %q", string(content), string(testContent))
	}

	// Test directory traversal protection
	_, err = backend.GetFileByPath("/etc/passwd")
	if err == nil {
		t.Error("expected error for path outside base directory, got nil")
	}

	// Test file not found
	_, err = backend.GetFileByPath("nonexistent.yaml")
	if !IsNotExist(err) {
		t.Errorf("expected ErrNotExist, got %v", err)
	}
}

func TestFileSystemBackend_ListFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	files := []string{"app1-prod.yaml", "app2-prod.json", "app3-dev.yml"}
	for _, f := range files {
		err := os.WriteFile(filepath.Join(tmpDir, f), []byte("test"), 0644)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	backend := NewFileSystemBackend(tmpDir)

	list, err := backend.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles returned error: %v", err)
	}

	if len(list) != len(files) {
		t.Errorf("expected %d files, got %d", len(files), len(list))
	}
}
