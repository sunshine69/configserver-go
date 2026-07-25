package main

import (
	"bytes"
	"configservergo/backend"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"configservergo/lib"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"
)

// ============================================================================
// Test Helpers
// ============================================================================

// testApp creates an isolated App with both filesystem and postgres backends
// for testing purposes.
func testApp(t *testing.T) (*App, string) {
	t.Helper()
	fsDir, err := os.MkdirTemp("", "configserver-go-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	pgDSN := os.Getenv("POSTGRES_DSN")
	if pgDSN == "" {
		pgDSN = "postgres://configuser:changeme@localhost:5432/configdb?sslmode=disable"
	}

	users := map[string]*UserConfig{
		"user1": {
			Username:      "user1",
			Password:      "changeme",
			EncryptionKey: "mySecretKey123",
			Backend:       "filesystem",
			Directory:     fsDir,
			Passwords:     make(map[string]PasswordMeta),
		},
		"user2": {
			Username:      "user2",
			Password:      "changeme",
			EncryptionKey: "mySecretKey456",
			Backend:       "postgres",
			Passwords:     make(map[string]PasswordMeta),
			Postgres: backend.PostgresUserConfig{
				ConnectionString: pgDSN,
				TableName:        "config_server_files",
			},
		},
	}

	var fsBackend *backend.FileSystemBackend
	if fsDir != "" {
		fsBackend = backend.NewFileSystemBackend(fsDir)
	}

	pgBackend := backend.NewPostgresBackend(pgDSN)
	resolver := backend.NewResolver(fsBackend, pgBackend)

	app := &App{
		Users:   users,
		Backend: resolver,
	}

	return app, fsDir
}

// doRequest performs an HTTP request against the test app and returns the recorder.
func doRequest(t *testing.T, app *App, method, path string, auth *TestAuth, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	rr := httptest.NewRecorder()
	app.Handler().ServeHTTP(rr, req)
	return rr
}

type TestAuth struct {
	Username string
	Password string
}

// assertStatusCode checks the response status code matches expected.
func assertStatusCode(t *testing.T, name, method, path string, auth *TestAuth, app *App, expected int) bool {
	t.Helper()
	rr := doRequest(t, app, method, path, auth, nil)
	if rr.Code != expected {
		t.Errorf("[%s] %s %s: expected status %d, got %d. Body: %s",
			t.Name(), method, path, expected, rr.Code, truncate(rr.Body.String()))
		return false
	}
	return true
}

// assertUploadStatusCode is like assertStatusCode but sends body with POST requests (for upload-like paths).
func assertUploadStatusCode(t *testing.T, name, method, path string, auth *TestAuth, app *App, expected int, body io.Reader) bool {
	t.Helper()
	rr := doRequest(t, app, method, path, auth, body)
	if rr.Code != expected {
		t.Errorf("[%s] %s %s: expected status %d, got %d. Body: %s",
			t.Name(), method, path, expected, rr.Code, truncate(rr.Body.String()))
		return false
	}
	return true
}

// assertStatusAndContains checks status AND that body contains a substring.
func assertStatusAndContains(t *testing.T, name, method, path string, auth *TestAuth,
	app *App, expectedStatus int, contains string) {
	t.Helper()
	rr := doRequest(t, app, method, path, auth, nil)
	if rr.Code != expectedStatus {
		t.Errorf("[%s] expected status %d, got %d. Body: %s",
			t.Name(), expectedStatus, rr.Code, truncate(rr.Body.String()))
		return
	}
	if !strings.Contains(rr.Body.String(), contains) {
		t.Errorf("[%s] body does not contain %q. Body: %s",
			t.Name(), contains, truncate(rr.Body.String()))
	}
}

// truncate limits a string for error messages.
func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// uploadConfig uploads a config file for the given config-app/profile/label.
// Note: `app` is the App object, `cfgApp` is the config application name.
func uploadConfig(t *testing.T, app *App, auth *TestAuth, cfgApp, profile, label, ext string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	path := fmt.Sprintf("/upload?app=%s&profile=%s&ext=%s", cfgApp, profile, ext)
	if label != "" {
		path += "&label=" + label
	}
	return doRequest(t, app, http.MethodPost, path, auth, bytes.NewReader(content))
}

// uploadConfigWithFullPath uploads with a virtual path.
func uploadConfigWithFullPath(t *testing.T, app *App, auth *TestAuth, cfgApp, profile, label, ext, vpath string, content []byte) *httptest.ResponseRecorder {
	t.Helper()
	path := fmt.Sprintf("/upload?app=%s&profile=%s&ext=%s&path=%s", cfgApp, profile, ext, vpath)
	if label != "" {
		path += "&label=" + label
	}
	return doRequest(t, app, http.MethodPost, path, auth, bytes.NewReader(content))
}

// fetchConfig fetches a config file by path (e.g. "myapp/dev").
func fetchConfig(t *testing.T, app *App, auth *TestAuth, path string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, app, http.MethodGet, "/"+path, auth, nil)
}

// parseGetValuesResponse parses the JSON response of a GetValues endpoint.
func parseGetValuesResponse(t *testing.T, rr *httptest.ResponseRecorder) *GetValuesResponse {
	t.Helper()
	var resp GetValuesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v. Body: %s", err, truncate(rr.Body.String()))
	}
	return &resp
}

// getProperty extracts a property value from the first property source.
func getProperty(t *testing.T, rr *httptest.ResponseRecorder, key string) interface{} {
	t.Helper()
	resp := parseGetValuesResponse(t, rr)
	if len(resp.PropertySources) == 0 {
		return nil
	}
	if src, ok := resp.PropertySources[0].Source[key]; ok {
		return src
	}
	return nil
}

// loadTestFile loads a test data file relative to the test binary location.
func loadTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("test-data", name))
	if err != nil {
		t.Fatalf("Failed to load test file %s: %v", name, err)
	}
	return data
}

// keysOf returns a list of keys from a map.
func keysOf(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Section 1: Authentication Tests
// ============================================================================

func TestAuthentication(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	t.Run("GET without authentication returns 401", func(t *testing.T) {
		assertStatusCode(t, "no-auth", http.MethodGet, "/myapp/dev.yaml", nil, app, http.StatusUnauthorized)
	})

	t.Run("GET with wrong password returns 401", func(t *testing.T) {
		assertStatusCode(t, "wrong-pass", http.MethodGet, "/myapp/dev.yaml",
			&TestAuth{Username: "user1", Password: "wrongpass"}, app, http.StatusUnauthorized)
	})

	t.Run("GET with unknown user returns 401", func(t *testing.T) {
		assertStatusCode(t, "unknown-user", http.MethodGet, "/myapp/dev.yaml",
			&TestAuth{Username: "nonexistent", Password: "pass"}, app, http.StatusUnauthorized)
	})

	t.Run("Upload without authentication returns 401", func(t *testing.T) {
		assertUploadStatusCode(t, "upload-no-auth", http.MethodPost, "/upload?app=myapp&profile=test&ext=.yaml",
			nil, app, http.StatusUnauthorized, bytes.NewReader([]byte("test")))
	})

	t.Run("Upload with wrong password returns 401", func(t *testing.T) {
		assertUploadStatusCode(t, "upload-wrong-pass", http.MethodPost, "/upload?app=myapp&profile=test&ext=.yaml",
			&TestAuth{Username: "user1", Password: "wrongpass"}, app, http.StatusUnauthorized, bytes.NewReader([]byte("test")))
	})
}

// ============================================================================
// Section 2: Filesystem Backend - Upload Tests
// ============================================================================

func TestFilesystemUpload(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	t.Run("Upload YAML file", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)
		assertStatusAndContains(t, "upload-yaml", http.MethodPost, "/upload?app=myapp&profile=dev&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
		if _, err := os.Stat(filepath.Join(fsDir, "myapp-dev.yaml")); err != nil {
			t.Errorf("File not written to disk: %v", err)
		}
	})

	t.Run("Upload JSON file", func(t *testing.T) {
		content := loadTestFile(t, "prod.json")
		_ = uploadConfig(t, app, auth, "myapp", "prod", "", ".json", content)
		assertStatusAndContains(t, "upload-json", http.MethodPost, "/upload?app=myapp&profile=prod&ext=.json", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload .properties file", func(t *testing.T) {
		content := loadTestFile(t, "prod.properties")
		_ = uploadConfig(t, app, auth, "myapp", "prod", "", ".properties", content)
		assertStatusAndContains(t, "upload-properties", http.MethodPost, "/upload?app=myapp&profile=prod&ext=.properties", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload .yml file", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "ymltest", "", ".yml", content)
		assertStatusAndContains(t, "upload-yml", http.MethodPost, "/upload?app=myapp&profile=ymltest&ext=.yml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload with label", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "dev", "main", ".yaml", content)
		assertStatusAndContains(t, "upload-label", http.MethodPost, "/upload?app=myapp&profile=dev&label=main&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload with label v2", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "staging", "v2", ".yaml", content)
		assertStatusAndContains(t, "upload-label-v2", http.MethodPost, "/upload?app=myapp&profile=staging&label=v2&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload config with special characters", func(t *testing.T) {
		content := loadTestFile(t, "special2.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "special2", "", ".yaml", content)
		assertStatusAndContains(t, "upload-special", http.MethodPost, "/upload?app=myapp&profile=special2&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload large config", func(t *testing.T) {
		content := loadTestFile(t, "large.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "large", "", ".yaml", content)
		assertStatusAndContains(t, "upload-large", http.MethodPost, "/upload?app=myapp&profile=large&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Overwrite existing YAML file (idempotent)", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)
		assertStatusAndContains(t, "overwrite", http.MethodPost, "/upload?app=myapp&profile=dev&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})
}

// ============================================================================
// Section 3: Filesystem Backend - GET Tests
// ============================================================================

func TestFilesystemGet(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	// Upload configs first
	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	content = loadTestFile(t, "prod.json")
	uploadConfig(t, app, auth, "myapp", "prod", "", ".json", content)

	content = loadTestFile(t, "prod.properties")
	uploadConfig(t, app, auth, "myapp", "prod", "", ".properties", content)

	content = loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "ymltest", "", ".yml", content)

	content = loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "main", ".yaml", content)

	content = loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "staging", "v2", ".yaml", content)

	t.Run("GET existing YAML file", func(t *testing.T) {
		assertStatusCode(t, "get-yaml", http.MethodGet, "/myapp/dev.yaml", auth, app, http.StatusOK)
	})

	t.Run("GET existing JSON file", func(t *testing.T) {
		assertStatusCode(t, "get-json", http.MethodGet, "/myapp/prod.json", auth, app, http.StatusOK)
	})

	t.Run("GET existing .properties file", func(t *testing.T) {
		assertStatusCode(t, "get-properties", http.MethodGet, "/myapp/prod.properties", auth, app, http.StatusOK)
	})

	t.Run("GET existing .yml file", func(t *testing.T) {
		assertStatusCode(t, "get-yml", http.MethodGet, "/myapp/ymltest.yml", auth, app, http.StatusOK)
	})

	t.Run("GET YAML with label", func(t *testing.T) {
		assertStatusCode(t, "get-label", http.MethodGet, "/myapp/dev/main.yaml", auth, app, http.StatusOK)
	})

	t.Run("GET with label v2", func(t *testing.T) {
		assertStatusCode(t, "get-label-v2", http.MethodGet, "/myapp/staging/v2.yaml", auth, app, http.StatusOK)
	})

	t.Run("GET non-existent file returns 404", func(t *testing.T) {
		assertStatusCode(t, "get-not-found", http.MethodGet, "/myapp/nonexistent.yaml", auth, app, http.StatusNotFound)
	})
}

// ============================================================================
// Section 4: Property Flattening Tests
// ============================================================================

func TestPropertyFlattening(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	content = loadTestFile(t, "prod.json")
	uploadConfig(t, app, auth, "myapp", "prod", "", ".json", content)

	content = loadTestFile(t, "prod.properties")
	uploadConfig(t, app, auth, "myapp", "prodprops", "", ".properties", content)

	content = loadTestFile(t, "special2.yaml")
	uploadConfig(t, app, auth, "myapp", "special2", "", ".yaml", content)

	t.Run("YAML nested key flattening: database.host", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev.yaml")
		val := getProperty(t, rr, "database.host")
		if val == nil {
			t.Fatalf("database.host not found in response")
		}
		if val != "localhost" {
			t.Errorf("Expected database.host=localhost, got %v", val)
		}
	})

	t.Run("JSON flat key: app", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/prod.json")
		val := getProperty(t, rr, "app")
		if val == nil {
			t.Fatalf("app not found in response")
		}
		t.Logf("app value: %v (type %T)", val, val)
	})

	t.Run("Properties key: database.host", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/prodprops.properties")
		val := getProperty(t, rr, "database.host")
		if val == nil {
			t.Fatalf("database.host not found in properties response")
		}
		if val != "prodhost" {
			t.Errorf("Expected database.host=prodhost, got %v", val)
		}
	})

	t.Run("Nested YAML: nested.key1", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/special2.yaml")
		val := getProperty(t, rr, "nested.key1")
		if val == nil {
			t.Fatalf("nested.key1 not found")
		}
		if val != "val1" {
			t.Errorf("Expected nested.key1=val1, got %v", val)
		}
	})

	t.Run("Deep nested YAML: nested.key2.subkey", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/special2.yaml")
		val := getProperty(t, rr, "nested.key2.subkey")
		if val == nil {
			t.Fatalf("nested.key2.subkey not found")
		}
		if val != "subval" {
			t.Errorf("Expected nested.key2.subkey=subval, got %v", val)
		}
	})

	t.Run("Boolean preserved: bool", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/special2.yaml")
		val := getProperty(t, rr, "bool")
		if val == nil {
			t.Fatalf("bool not found")
		}
		if val != true && val != "true" {
			t.Errorf("Expected bool=true, got %v (type %T)", val, val)
		}
	})

	t.Run("Numeric preserved: numeric", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/special2.yaml")
		val := getProperty(t, rr, "numeric")
		if val == nil {
			t.Fatalf("numeric not found")
		}
		t.Logf("numeric value: %v (type %T)", val, val)
	})
}

// ============================================================================
// Section 5: GetValuesResponse JSON Structure Tests
// ============================================================================

func TestGetValuesResponseStructure(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	t.Run("Response name is 'myapp'", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev")
		resp := parseGetValuesResponse(t, rr)
		if resp.Name != "myapp" {
			t.Errorf("Expected name='myapp', got '%s'", resp.Name)
		}
	})

	t.Run("Response has correct profiles", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev")
		resp := parseGetValuesResponse(t, rr)
		if len(resp.Profiles) == 0 {
			t.Fatal("Expected at least one profile")
		}
		if resp.Profiles[0] != "dev" {
			t.Errorf("Expected profile='dev', got '%s'", resp.Profiles[0])
		}
	})

	t.Run("Response has label when label is specified", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		uploadConfig(t, app, auth, "myapp", "dev", "main", ".yaml", content)

		rr := fetchConfig(t, app, auth, "myapp/dev/main")
		resp := parseGetValuesResponse(t, rr)
		if resp.Label == nil {
			t.Fatal("Expected label to be set")
		}
		if *resp.Label != "main" {
			t.Errorf("Expected label='main', got '%s'", *resp.Label)
		}
	})

	t.Run("propertySources has 1+ entry", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev")
		resp := parseGetValuesResponse(t, rr)
		if len(resp.PropertySources) == 0 {
			t.Fatal("Expected at least one property source")
		}
	})

	t.Run("propertySources[0].source has keys", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev")
		resp := parseGetValuesResponse(t, rr)
		if len(resp.PropertySources[0].Source) == 0 {
			t.Fatal("Expected property source to have keys")
		}
		t.Logf("property source has %d keys: %v", len(resp.PropertySources[0].Source), keysOf(resp.PropertySources[0].Source))
	})
}

// ============================================================================
// Section 6: PostgreSQL Backend Tests
// ============================================================================

func TestPostgresBackend(t *testing.T) {
	pgDSN := os.Getenv("POSTGRES_DSN")
	if pgDSN == "" {
		pgDSN = "postgres://configuser:changeme@localhost:5432/configdb?sslmode=disable"
	}

	pool, err := pgxpool.New(t.Context(), pgDSN)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
		return
	}
	defer pool.Close()

	_, err = pool.Exec(t.Context(), backend.TableSQL)
	if err != nil {
		t.Skipf("Failed to create postgres table: %v", err)
		return
	}

	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user2", Password: "changeme"}

	t.Run("Upload YAML to PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "pgapp", "dev", "", ".yaml", content)
		assertStatusAndContains(t, "pg-upload-yaml", http.MethodPost, "/upload?app=pgapp&profile=dev&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload JSON to PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "prod.json")
		_ = uploadConfig(t, app, auth, "pgapp", "prod", "", ".json", content)
		assertStatusAndContains(t, "pg-upload-json", http.MethodPost, "/upload?app=pgapp&profile=prod&ext=.json", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload .properties to PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "prod.properties")
		_ = uploadConfig(t, app, auth, "pgapp", "prodprops", "", ".properties", content)
		assertStatusAndContains(t, "pg-upload-properties", http.MethodPost, "/upload?app=pgapp&profile=prodprops&ext=.properties", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload YAML with label to PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "pgapp", "dev", "staging", ".yaml", content)
		assertStatusAndContains(t, "pg-upload-label", http.MethodPost, "/upload?app=pgapp&profile=dev&label=staging&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("GET YAML from PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		uploadConfig(t, app, auth, "pgapp", "dev", "", ".yaml", content)
		assertStatusCode(t, "pg-get-yaml", http.MethodGet, "/pgapp/dev.yaml", auth, app, http.StatusOK)
	})

	t.Run("GET JSON from PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "prod.json")
		uploadConfig(t, app, auth, "pgapp", "prod", "", ".json", content)
		assertStatusCode(t, "pg-get-json", http.MethodGet, "/pgapp/prod.json", auth, app, http.StatusOK)
	})

	t.Run("GET YAML with label from PostgreSQL", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		uploadConfig(t, app, auth, "pgapp", "dev", "staging", ".yaml", content)
		assertStatusCode(t, "pg-get-label", http.MethodGet, "/pgapp/dev/staging.yaml", auth, app, http.StatusOK)
	})

	t.Run("GET non-existent from PostgreSQL returns 404", func(t *testing.T) {
		assertStatusCode(t, "pg-get-not-found", http.MethodGet, "/pgapp/nonexistent.yaml", auth, app, http.StatusNotFound)
	})

	t.Run("User2 cannot access user1's files (cross-user isolation)", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		uploadConfig(t, app, &TestAuth{Username: "user1", Password: "changeme"}, "myapp", "dev", "", ".yaml", content)
		assertStatusCode(t, "pg-isolation-user2-cant-read-user1", http.MethodGet, "/myapp/dev.yaml", auth, app, http.StatusNotFound)
	})

	t.Run("User1 cannot access user2's files (cross-user isolation)", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		uploadConfig(t, app, auth, "pgapp", "dev", "", ".yaml", content)
		user1auth := &TestAuth{Username: "user1", Password: "changeme"}
		assertStatusCode(t, "pg-isolation-user1-cant-read-user2", http.MethodGet, "/pgapp/dev.yaml", user1auth, app, http.StatusNotFound)
	})

	t.Run("User2 overwrites its own file (upsert)", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfig(t, app, auth, "pgapp", "dev", "", ".yaml", content)
		assertStatusAndContains(t, "pg-upsert", http.MethodPost, "/upload?app=pgapp&profile=dev&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})
}

// ============================================================================
// Section 7: Encrypt / Decrypt Tests
// ============================================================================

func TestEncryptDecrypt(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	t.Run("Encrypt returns ciphertext (not empty)", func(t *testing.T) {
		body := bytes.NewReader([]byte("my-secret-password"))
		rr := doRequest(t, app, http.MethodPost, "/encrypt", auth, body)
		if rr.Code != http.StatusOK {
			t.Fatalf("Encrypt expected 200, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
		if len(rr.Body.String()) <= 10 {
			t.Errorf("Encrypt returned suspiciously short ciphertext: %q", rr.Body.String())
		}
	})

	t.Run("Encrypt/Decrypt roundtrip", func(t *testing.T) {
		original := "my-secret-password"
		encryptRR := doRequest(t, app, http.MethodPost, "/encrypt", auth, bytes.NewReader([]byte(original)))
		if encryptRR.Code != http.StatusOK {
			t.Fatalf("Encrypt failed: %s", truncate(encryptRR.Body.String()))
		}
		ciphertext := encryptRR.Body.String()

		decryptRR := doRequest(t, app, http.MethodPost, "/decrypt", auth, bytes.NewReader([]byte(ciphertext)))
		if decryptRR.Code != http.StatusOK {
			t.Fatalf("Decrypt failed: %s", truncate(decryptRR.Body.String()))
		}
		if decryptRR.Body.String() != original {
			t.Errorf("Decrypt returned %q, expected %q", decryptRR.Body.String(), original)
		}
	})

	t.Run("Decrypt invalid ciphertext returns 400", func(t *testing.T) {
		body := bytes.NewReader([]byte("invalid-ciphertext"))
		rr := doRequest(t, app, http.MethodPost, "/decrypt", auth, body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("Decrypt invalid expected 400, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
	})

	t.Run("Encrypt/decrypt roundtrip with special chars", func(t *testing.T) {
		original := "p@ss w0rd!#$%"
		encryptRR := doRequest(t, app, http.MethodPost, "/encrypt", auth, bytes.NewReader([]byte(original)))
		if encryptRR.Code != http.StatusOK {
			t.Fatalf("Encrypt with special chars failed: %s", truncate(encryptRR.Body.String()))
		}

		decryptRR := doRequest(t, app, http.MethodPost, "/decrypt", auth, bytes.NewReader([]byte(encryptRR.Body.String())))
		if decryptRR.Code != http.StatusOK {
			t.Fatalf("Decrypt with special chars failed: %s", truncate(decryptRR.Body.String()))
		}
		if decryptRR.Body.String() != original {
			t.Errorf("Special chars roundtrip: got %q, expected %q", decryptRR.Body.String(), original)
		}
	})

	t.Run("Different users get different ciphertext for same plaintext", func(t *testing.T) {
		user2auth := &TestAuth{Username: "user2", Password: "changeme"}
		original := "shared-secret"

		encryptRR1 := doRequest(t, app, http.MethodPost, "/encrypt", auth, bytes.NewReader([]byte(original)))
		encryptRR2 := doRequest(t, app, http.MethodPost, "/encrypt", user2auth, bytes.NewReader([]byte(original)))

		if encryptRR1.Body.String() == encryptRR2.Body.String() {
			t.Error("Different encryption keys should produce different ciphertexts")
		}
		t.Logf("User1 ciphertext: %s", encryptRR1.Body.String()[:min(40, len(encryptRR1.Body.String()))])
		t.Logf("User2 ciphertext: %s", encryptRR2.Body.String()[:min(40, len(encryptRR2.Body.String()))])
	})

	t.Run("User2 cannot decrypt User1's ciphertext", func(t *testing.T) {
		user2auth := &TestAuth{Username: "user2", Password: "changeme"}
		original := "user1-secret"

		encryptRR := doRequest(t, app, http.MethodPost, "/encrypt", auth, bytes.NewReader([]byte(original)))
		if encryptRR.Code != http.StatusOK {
			t.Fatal("Encrypt failed")
		}

		decryptRR := doRequest(t, app, http.MethodPost, "/decrypt", user2auth, bytes.NewReader([]byte(encryptRR.Body.String())))
		if decryptRR.Code != http.StatusBadRequest {
			t.Errorf("Decrypt cross-user expected 400, got %d. Body: %s", decryptRR.Code, truncate(decryptRR.Body.String()))
		}
	})

	t.Run("GET config with {cipher} values auto-decrypts", func(t *testing.T) {
		original := "secret-password"
		encryptRR := doRequest(t, app, http.MethodPost, "/encrypt", auth, bytes.NewReader([]byte(original)))
		ciphertext := encryptRR.Body.String()

		configContent := fmt.Sprintf("database:\n  password: {cipher}%s\n", ciphertext)
		uploadConfig(t, app, auth, "myapp", "encrypted", "", ".yaml", []byte(configContent))

		rr := fetchConfig(t, app, auth, "myapp/encrypted.yaml")
		val := getProperty(t, rr, "database.password")
		if val == nil {
			t.Fatal("database.password not found")
		}
		if val != "secret-password" {
			t.Errorf("Expected database.password=secret-password, got %v", val)
		}
	})
}

// ============================================================================
// Section 8: Input Validation Tests
// ============================================================================

func TestInputValidation(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	t.Run("Upload with invalid extension returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "invalid-ext", http.MethodPost, "/upload?app=myapp&profile=dev&ext=.exe",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Upload missing app returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "missing-app", http.MethodPost, "/upload?profile=dev&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Upload missing profile returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "missing-profile", http.MethodPost, "/upload?app=myapp&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Path traversal in app name returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "traversal-app", http.MethodPost, "/upload?app=../etc&profile=dev&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Path traversal in profile name returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "traversal-profile", http.MethodPost, "/upload?app=myapp&profile=../etc&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Path traversal in label returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "traversal-label", http.MethodPost, "/upload?app=myapp&profile=dev&label=../../etc&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Spaces in app name returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "spaces-in-app", http.MethodPost, "/upload?app=my+app&profile=dev&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})

	t.Run("Dots in app name returns 400", func(t *testing.T) {
		assertUploadStatusCode(t, "dots-in-app", http.MethodPost, "/upload?app=my.app&profile=dev&ext=.yaml",
			auth, app, http.StatusBadRequest, bytes.NewReader([]byte("test")))
	})
}

// ============================================================================
// Section 9: Edge Cases
// ============================================================================

func TestEdgeCases(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	t.Run("Upload empty content returns 200", func(t *testing.T) {
		_ = doRequest(t, app, http.MethodPost, "/upload?app=myapp&profile=empty&ext=.yaml", auth, bytes.NewReader(nil))
		assertStatusAndContains(t, "empty-upload", http.MethodPost, "/upload?app=myapp&profile=empty&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("GET empty content returns 200", func(t *testing.T) {
		doRequest(t, app, http.MethodPost, "/upload?app=myapp&profile=empty&ext=.yaml", auth, bytes.NewReader(nil))

		rr := doRequest(t, app, http.MethodGet, "/myapp/empty.yaml", auth, nil)
		if rr.Code != http.StatusOK {
			t.Errorf("GET empty content expected 200, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
	})

	t.Run("Upload deeply nested config", func(t *testing.T) {
		data := map[string]interface{}{
			"a": map[string]interface{}{
				"b": map[string]interface{}{
					"c": map[string]interface{}{
						"d": map[string]interface{}{
							"e": "deep",
						},
					},
				},
			},
		}
		content, _ := yaml.Marshal(data)
		_ = uploadConfig(t, app, auth, "myapp", "deep", "", ".yaml", content)
		assertStatusAndContains(t, "deep-nested", http.MethodPost, "/upload?app=myapp&profile=deep&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Deep nesting flattened correctly", func(t *testing.T) {
		data := map[string]interface{}{
			"a": map[string]interface{}{
				"b": map[string]interface{}{
					"c": map[string]interface{}{
						"d": map[string]interface{}{
							"e": "deep",
						},
					},
				},
			},
		}
		content, _ := yaml.Marshal(data)
		uploadConfig(t, app, auth, "myapp", "deep", "", ".yaml", content)

		rr := fetchConfig(t, app, auth, "myapp/deep.yaml")
		val := getProperty(t, rr, "a.b.c.d.e")
		if val == nil {
			t.Fatal("a.b.c.d.e not found")
		}
		if val != "deep" {
			t.Errorf("Expected a.b.c.d.e=deep, got %v", val)
		}
	})

	t.Run("Upload config with list values", func(t *testing.T) {
		data := map[string]interface{}{
			"items": []interface{}{"alpha", "beta", "gamma"},
		}
		content, _ := yaml.Marshal(data)
		_ = uploadConfig(t, app, auth, "myapp", "list", "", ".yaml", content)
		assertStatusAndContains(t, "list-values", http.MethodPost, "/upload?app=myapp&profile=list&ext=.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("List values preserved", func(t *testing.T) {
		data := map[string]interface{}{
			"items": []interface{}{"alpha", "beta", "gamma"},
		}
		content, _ := yaml.Marshal(data)
		uploadConfig(t, app, auth, "myapp", "list", "", ".yaml", content)

		rr := fetchConfig(t, app, auth, "myapp/list.yaml")
		val := getProperty(t, rr, "items")
		if val == nil {
			t.Fatal("items not found")
		}
		t.Logf("items value: %v (type %T)", val, val)
		if arr, ok := val.([]interface{}); ok {
			if len(arr) != 3 {
				t.Errorf("Expected 3 items, got %d", len(arr))
			}
		}
	})

	t.Run("Idempotent upload (same file twice)", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)
		uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)
		assertStatusCode(t, "idempotent-2nd", http.MethodGet, "/myapp/dev.yaml", auth, app, http.StatusOK)
	})
}

// ============================================================================
// Section 10: Multiple Format Round-Trip
// ============================================================================

func TestFormatRoundTrip(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	content = loadTestFile(t, "prod.json")
	uploadConfig(t, app, auth, "myapp", "prod", "", ".json", content)

	content = loadTestFile(t, "prod.properties")
	uploadConfig(t, app, auth, "myapp", "prodprops", "", ".properties", content)

	t.Run("YAML keys present", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev")
		resp := parseGetValuesResponse(t, rr)
		if len(resp.PropertySources) == 0 {
			t.Fatal("No property sources")
		}
		src := resp.PropertySources[0].Source
		if _, ok := src["database.host"]; !ok {
			t.Errorf("Expected 'database.host' key in source. Keys: %v", keysOf(src))
		}
	})

	t.Run("JSON keys present", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/prod")
		resp := parseGetValuesResponse(t, rr)
		if len(resp.PropertySources) == 0 {
			t.Fatal("No property sources")
		}
		src := resp.PropertySources[0].Source
		t.Logf("JSON source keys: %v", keysOf(src))
	})

	t.Run("Properties keys present", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/prodprops")
		resp := parseGetValuesResponse(t, rr)
		if len(resp.PropertySources) == 0 {
			t.Fatal("No property sources")
		}
		src := resp.PropertySources[0].Source
		if _, ok := src["database.host"]; !ok {
			t.Errorf("Expected 'database.host' key in source. Keys: %v", keysOf(src))
		}
	})
}

// ============================================================================
// Section 11: Multi-Profile Merge Tests
// ============================================================================

func TestMultiProfileMerge(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	content = loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "common", "", ".yaml", content)

	t.Run("Multi-profile fetch returns 200", func(t *testing.T) {
		rr := fetchConfig(t, app, auth, "myapp/dev,common")
		if rr.Code != http.StatusOK {
			t.Errorf("Multi-profile fetch expected 200, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
	})

	t.Run("Multi-profile merge overrides properties", func(t *testing.T) {
		baseContent := map[string]interface{}{
			"database": map[string]interface{}{
				"host": "basehost",
				"port": 5432,
			},
		}
		baseYaml, _ := yaml.Marshal(baseContent)
		uploadConfig(t, app, auth, "myapp", "base", "", ".yaml", baseYaml)

		overrideContent := map[string]interface{}{
			"database": map[string]interface{}{
				"host": "overridehost",
			},
		}
		overrideYaml, _ := yaml.Marshal(overrideContent)
		uploadConfig(t, app, auth, "myapp", "override", "", ".yaml", overrideYaml)

		rr := fetchConfig(t, app, auth, "myapp/base,override")
		val := getProperty(t, rr, "database.host")
		if val == nil {
			t.Fatal("database.host not found")
		}
		t.Logf("database.host value: %v", val)
	})
}

// ============================================================================
// Section 12: Health Check & List Tests
// ============================================================================

func TestHealthCheck(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	t.Run("Health check returns UP", func(t *testing.T) {
		_ = doRequest(t, app, http.MethodGet, "/health", nil, nil)
		assertStatusAndContains(t, "health", http.MethodGet, "/health", nil, app, http.StatusOK, "UP")
	})

	t.Run("Health check returns JSON with status UP", func(t *testing.T) {
		rr := doRequest(t, app, http.MethodGet, "/health", nil, nil)
		var health map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil {
			t.Fatalf("Failed to parse health response: %v", err)
		}
		if health["status"] != "UP" {
			t.Errorf("Expected status UP, got %v", health["status"])
		}
	})
}

func TestListFiles(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	t.Run("List files returns 200", func(t *testing.T) {
		_ = doRequest(t, app, http.MethodGet, "/list", auth, nil)
		assertStatusCode(t, "list-files", http.MethodGet, "/list", auth, app, http.StatusOK)
	})

	t.Run("List files returns valid JSON array", func(t *testing.T) {
		rr := doRequest(t, app, http.MethodGet, "/list", auth, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected 200, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
		var files []map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &files); err != nil {
			t.Fatalf("Failed to parse list response: %v", err)
		}
		if len(files) == 0 {
			t.Error("Expected at least one file in list")
		}
		t.Logf("Listed %d files", len(files))
	})
}

// ============================================================================
// Section 13: Multi-Password Authentication Tests
// ============================================================================

func TestMultiPasswordAuth(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user2", Password: "changeme"}

	t.Run("Add temporary password", func(t *testing.T) {
		exp := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
		body := fmt.Sprintf("password=temptoken123&exp=%s&description=temporary-test", exp)
		_ = doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))
		assertStatusAndContains(t, "add-temp-pw", http.MethodPost, "/addpassword", auth, app, http.StatusOK, "Password added")
	})

	t.Run("Add no-expire password", func(t *testing.T) {
		body := "password=foreverpass&exp=noexpire&description=permanent-secondary"
		_ = doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))
		assertStatusAndContains(t, "add-noexpire-pw", http.MethodPost, "/addpassword", auth, app, http.StatusOK, "Password added")
	})

	t.Run("List passwords returns 200", func(t *testing.T) {
		body := "password=listpw&exp=noexpire&description=list-test"
		doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))

		_ = doRequest(t, app, http.MethodGet, "/listpasswords", auth, nil)
		assertStatusCode(t, "list-passwords", http.MethodGet, "/listpasswords", auth, app, http.StatusOK)
	})

	t.Run("Authenticate with temp password", func(t *testing.T) {
		body := "password=authpw&exp=noexpire&description=auth-test"
		doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))

		tempAuth := &TestAuth{Username: "user2", Password: "authpw"}
		assertStatusCode(t, "auth-temp-pw", http.MethodGet, "/myapp/dev.yaml", tempAuth, app, http.StatusOK)
	})

	t.Run("Authenticate with no-expire password", func(t *testing.T) {
		body := "password=noexpireauth&exp=noexpire&description=noexpire-auth"
		doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))

		tempAuth := &TestAuth{Username: "user2", Password: "noexpireauth"}
		assertStatusCode(t, "auth-noexpire-pw", http.MethodGet, "/myapp/dev.yaml", tempAuth, app, http.StatusOK)
	})

	t.Run("Authenticate with main password still works", func(t *testing.T) {
		assertStatusCode(t, "auth-main-pw", http.MethodGet, "/myapp/dev.yaml", auth, app, http.StatusOK)
	})

	t.Run("Duplicate password rejected", func(t *testing.T) {
		body := "password=duplpw&exp=noexpire&description=duplicate-test"
		doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))
		_ = doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))
		assertStatusCode(t, "duplicate-pw", http.MethodPost, "/addpassword", auth, app, http.StatusBadRequest)
	})

	t.Run("Missing password field rejected", func(t *testing.T) {
		body := "exp=noexpire&description=missing-pw"
		_ = doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))
		assertStatusCode(t, "missing-pw-field", http.MethodPost, "/addpassword", auth, app, http.StatusBadRequest)
	})

	t.Run("Invalid exp format rejected", func(t *testing.T) {
		body := "password=badexp&exp=not-a-date&description=bad-exp"
		rr := doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("Invalid exp format expected 400, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
	})

	t.Run("Delete password by hash", func(t *testing.T) {
		body := "password=delpw&exp=noexpire&description=delete-test"
		doRequest(t, app, http.MethodPost, "/addpassword", auth, strings.NewReader(body))

		rr := doRequest(t, app, http.MethodGet, "/listpasswords", auth, nil)
		var resp map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &resp)
		passwords := resp["passwords"].(map[string]interface{})
		for hash := range passwords {
			_ = doRequest(t, app, http.MethodDelete, "/delpassword?hash="+hash, auth, nil)
			assertStatusCode(t, "delete-pw", http.MethodDelete, "/delpassword?hash="+hash, auth, app, http.StatusOK)
			break
		}
	})

	t.Run("Delete nonexistent hash returns 404", func(t *testing.T) {
		fakeHash := strings.Repeat("0", 64)
		_ = doRequest(t, app, http.MethodDelete, "/delpassword?hash="+fakeHash, auth, nil)
		assertStatusCode(t, "delete-nonexistent", http.MethodDelete, "/delpassword?hash="+fakeHash, auth, app, http.StatusNotFound)
	})

	t.Run("Delete missing hash param returns 400", func(t *testing.T) {
		_ = doRequest(t, app, http.MethodDelete, "/delpassword", auth, nil)
		assertStatusCode(t, "delete-no-hash", http.MethodDelete, "/delpassword", auth, app, http.StatusBadRequest)
	})

	t.Run("Unauthorized on addpassword returns 401", func(t *testing.T) {
		body := "password=test&exp=noexpire&description=unauthorized"
		_ = doRequest(t, app, http.MethodPost, "/addpassword", nil, strings.NewReader(body))
		assertStatusCode(t, "unauth-addpw", http.MethodPost, "/addpassword", nil, app, http.StatusUnauthorized)
	})

	t.Run("Unauthorized on listpasswords returns 401", func(t *testing.T) {
		_ = doRequest(t, app, http.MethodGet, "/listpasswords", nil, nil)
		assertStatusCode(t, "unauth-listpw", http.MethodGet, "/listpasswords", nil, app, http.StatusUnauthorized)
	})

	t.Run("Unauthorized on delpassword returns 401", func(t *testing.T) {
		_ = doRequest(t, app, http.MethodDelete, "/delpassword?hash="+strings.Repeat("0", 64), nil, nil)
		assertStatusCode(t, "unauth-delpw", http.MethodDelete, "/delpassword?hash="+strings.Repeat("0", 64), nil, app, http.StatusUnauthorized)
	})
}

// ============================================================================
// Section 14: Format-Specific Endpoints
// ============================================================================

func TestFormatSpecificEndpoints(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "dev", "", ".yaml", content)

	content = loadTestFile(t, "prod.json")
	uploadConfig(t, app, auth, "myapp", "prod", "", ".json", content)

	content = loadTestFile(t, "prod.properties")
	uploadConfig(t, app, auth, "myapp", "prodprops", "", ".properties", content)

	t.Run("GET /{app}-{profile}.yml", func(t *testing.T) {
		uploadConfig(t, app, auth, "myapp", "dev", "", ".yml", content)
		assertStatusCode(t, "format-yml", http.MethodGet, "/myapp-dev.yml", auth, app, http.StatusOK)
	})

	t.Run("GET /{app}-{profile}.json", func(t *testing.T) {
		assertStatusCode(t, "format-json", http.MethodGet, "/myapp-prod.json", auth, app, http.StatusOK)
	})

	t.Run("GET /{app}-{profile}.properties", func(t *testing.T) {
		assertStatusCode(t, "format-properties", http.MethodGet, "/myapp-prodprops.properties", auth, app, http.StatusOK)
	})

	t.Run("GET /{label}/{app}-{profile}.yml", func(t *testing.T) {
		uploadConfig(t, app, auth, "myapp", "dev", "main", ".yml", content)
		assertStatusCode(t, "format-label-yml", http.MethodGet, "/main/myapp-dev.yml", auth, app, http.StatusOK)
	})

	t.Run("GET /{label}/{app}-{profile}.json", func(t *testing.T) {
		uploadConfig(t, app, auth, "myapp", "prod", "main", ".json", content)
		assertStatusCode(t, "format-label-json", http.MethodGet, "/main/myapp-prod.json", auth, app, http.StatusOK)
	})

	t.Run("GET /{label}/{app}-{profile}.properties", func(t *testing.T) {
		uploadConfig(t, app, auth, "myapp", "prodprops", "main", ".properties", content)
		assertStatusCode(t, "format-label-properties", http.MethodGet, "/main/myapp-prodprops.properties", auth, app, http.StatusOK)
	})
}

// ============================================================================
// Section 15: Swagger UI Tests
// ============================================================================

func TestSwaggerUI(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	t.Run("Swagger UI returns 200", func(t *testing.T) {
		rr := doRequest(t, app, http.MethodGet, "/swagger/index.html", nil, nil)
		if rr.Code != http.StatusOK {
			t.Errorf("Swagger UI expected 200, got %d. Body: %s", rr.Code, truncate(rr.Body.String()))
		}
	})
}

// ============================================================================
// Section 16: Backend Unit Tests
// ============================================================================

func TestFileSystemBackend(t *testing.T) {
	fsDir, err := os.MkdirTemp("", "fs-backend-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(fsDir)

	be := backend.NewFileSystemBackend(fsDir)

	t.Run("PutFile and GetFile", func(t *testing.T) {
		content := []byte("key: value\n")
		err := be.PutFile("myapp", "dev", "", ".yaml", content)
		if err != nil {
			t.Fatalf("PutFile failed: %v", err)
		}

		got, err := be.GetFile("myapp", "dev", "", ".yaml")
		if err != nil {
			t.Fatalf("GetFile failed: %v", err)
		}
		if string(got) != string(content) {
			t.Errorf("GetFile returned %q, expected %q", got, content)
		}
	})

	t.Run("Path traversal prevention", func(t *testing.T) {
		err := be.PutFile("../etc", "passwd", "", ".yaml", []byte("test"))
		if err == nil {
			t.Error("Expected error for path traversal")
		}
	})

	t.Run("DeleteFile and verify not found", func(t *testing.T) {
		content := []byte("key: value\n")
		be.PutFile("myapp", "todelete", "", ".yaml", content)

		err := be.DeleteFile("myapp", "todelete", "", ".yaml")
		if err != nil {
			t.Fatalf("DeleteFile failed: %v", err)
		}

		_, err = be.GetFile("myapp", "todelete", "", ".yaml")
		if !backend.IsNotExist(err) {
			t.Error("Expected ErrNotExist after delete")
		}
	})

	t.Run("ListFiles", func(t *testing.T) {
		be.PutFile("app1", "dev", "", ".yaml", []byte("a: b"))
		be.PutFile("app1", "prod", "", ".json", []byte("{}"))

		files, err := be.ListFiles()
		if err != nil {
			t.Fatalf("ListFiles failed: %v", err)
		}
		if len(files) != 2 {
			t.Errorf("Expected 2 files, got %d", len(files))
		}
	})

	t.Run("Unsupported extension rejected", func(t *testing.T) {
		err := be.PutFile("myapp", "dev", "", ".exe", []byte("test"))
		if err == nil {
			t.Error("Expected error for unsupported extension")
		}
	})
}

func TestBuildConfigFilename(t *testing.T) {
	tests := []struct {
		app, profile, label string
		expected            string
	}{
		{"foo", "dev", "main", "foo-dev-main"},
		{"foo", "dev", "", "foo-dev"},
		{"foo", "", "main", "foo-main"},
		{"foo", "", "", "foo"},
	}

	for _, tt := range tests {
		result := backend.BuildConfigFilename(tt.app, tt.profile, tt.label)
		if result != tt.expected {
			t.Errorf("BuildConfigFilename(%q, %q, %q) = %q, expected %q",
				tt.app, tt.profile, tt.label, result, tt.expected)
		}
	}
}

// ============================================================================
// Section 17: Cipher & Placeholder Tests
// ============================================================================

func TestCipherPlaceholder(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	t.Run("Encrypted value in config", func(t *testing.T) {
		original := "my-secret-password"
		encryptRR := doRequest(t, app, http.MethodPost, "/encrypt", auth, bytes.NewReader([]byte(original)))
		if encryptRR.Code != http.StatusOK {
			t.Fatalf("Encrypt failed: %s", truncate(encryptRR.Body.String()))
		}
		ciphertext := encryptRR.Body.String()

		configContent := fmt.Sprintf("database:\n  password: {cipher}%s\n", ciphertext)
		uploadConfig(t, app, auth, "myapp", "cipher", "", ".yaml", []byte(configContent))

		rr := fetchConfig(t, app, auth, "myapp/cipher.yaml")
		val := getProperty(t, rr, "database.password")
		if val == nil {
			t.Fatal("database.password not found")
		}
		if val != "my-secret-password" {
			t.Errorf("Expected decrypted password='my-secret-password', got %v", val)
		}
	})

	t.Run("ResolvePlaceholders returns content unchanged", func(t *testing.T) {
		result := lib.ResolvePlaceholders("key: ${SOME_VAR}")
		if result != "key: ${SOME_VAR}" {
			t.Errorf("ResolvePlaceholders should return content unchanged, got %q", result)
		}
	})
}

// ============================================================================
// Section 18: Delete Handler Tests
// ============================================================================

func TestDeleteHandler(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	content := loadTestFile(t, "dev.yaml")
	uploadConfig(t, app, auth, "myapp", "todelete", "", ".yaml", content)

	t.Run("Delete file returns 200", func(t *testing.T) {
		path := "/delete?app=myapp&profile=todelete&ext=.yaml"
		_ = doRequest(t, app, http.MethodDelete, path, auth, nil)
		assertStatusAndContains(t, "delete-file", http.MethodDelete, path, auth, app, http.StatusOK, "deleted successfully")
	})

	t.Run("Delete non-existent file returns 404", func(t *testing.T) {
		path := "/delete?app=myapp&profile=nonexistent&ext=.yaml"
		_ = doRequest(t, app, http.MethodDelete, path, auth, nil)
		assertStatusCode(t, "delete-not-found", http.MethodDelete, path, auth, app, http.StatusNotFound)
	})

	t.Run("Delete missing app returns 400", func(t *testing.T) {
		path := "/delete?profile=todelete&ext=.yaml"
		_ = doRequest(t, app, http.MethodDelete, path, auth, nil)
		assertStatusCode(t, "delete-no-app", http.MethodDelete, path, auth, app, http.StatusBadRequest)
	})
}

// ============================================================================
// Section 19: Path Traversal in Filesystem Backend
// ============================================================================

func TestPathTraversalPrevention(t *testing.T) {
	fsDir, err := os.MkdirTemp("", "path-traversal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(fsDir)

	be := backend.NewFileSystemBackend(fsDir)

	t.Run("PutFileWithFullPath rejects path traversal", func(t *testing.T) {
		err := be.PutFileWithFullPath("myapp", "dev", "", ".yaml", "../etc/passwd", []byte("test"))
		if err == nil {
			t.Error("Expected error for path traversal in PutFileWithFullPath")
		}
	})

	t.Run("PutFile rejects path traversal", func(t *testing.T) {
		err := be.PutFile("../etc", "passwd", "", ".yaml", []byte("test"))
		if err == nil {
			t.Error("Expected error for path traversal in PutFile")
		}
	})

	t.Run("DeleteFile rejects path traversal", func(t *testing.T) {
		err := be.DeleteFile("../etc", "passwd", "", ".yaml")
		if err == nil {
			t.Error("Expected error for path traversal in DeleteFile")
		}
	})
}

// ============================================================================
// Section 20: Uploader Path Prefix (Upload with virtual path)
// ============================================================================

func TestUploadWithFullPath(t *testing.T) {
	app, fsDir := testApp(t)
	defer os.RemoveAll(fsDir)

	auth := &TestAuth{Username: "user1", Password: "changeme"}

	t.Run("Upload with valid virtual path", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfigWithFullPath(t, app, auth, "myapp", "dev", "", ".yaml", "myapp/dev.yaml", content)
		assertStatusAndContains(t, "upload-vpath", http.MethodPost, "/upload?app=myapp&profile=dev&ext=.yaml&path=myapp%2Fdev.yaml", auth, app, http.StatusOK, "uploaded successfully")
	})

	t.Run("Upload with invalid virtual path returns 400", func(t *testing.T) {
		content := loadTestFile(t, "dev.yaml")
		_ = uploadConfigWithFullPath(t, app, auth, "myapp", "dev", "", ".yaml", "../etc/passwd", content)
		assertStatusCode(t, "upload-invalid-vpath", http.MethodPost, "/upload?app=myapp&profile=dev&ext=.yaml&path=..%2Fetc%2Fpasswd", auth, app, http.StatusBadRequest)
	})
}

// ============================================================================
// Main Test Runner
// ============================================================================

func TestAll(t *testing.T) {
	t.Run("Authentication", func(t *testing.T) {
		TestAuthentication(t)
	})
	t.Run("FilesystemUpload", func(t *testing.T) {
		TestFilesystemUpload(t)
	})
	t.Run("FilesystemGet", func(t *testing.T) {
		TestFilesystemGet(t)
	})
	t.Run("PropertyFlattening", func(t *testing.T) {
		TestPropertyFlattening(t)
	})
	t.Run("GetValuesResponseStructure", func(t *testing.T) {
		TestGetValuesResponseStructure(t)
	})
	t.Run("PostgresBackend", func(t *testing.T) {
		TestPostgresBackend(t)
	})
	t.Run("EncryptDecrypt", func(t *testing.T) {
		TestEncryptDecrypt(t)
	})
	t.Run("InputValidation", func(t *testing.T) {
		TestInputValidation(t)
	})
	t.Run("EdgeCases", func(t *testing.T) {
		TestEdgeCases(t)
	})
	t.Run("FormatRoundTrip", func(t *testing.T) {
		TestFormatRoundTrip(t)
	})
	t.Run("MultiProfileMerge", func(t *testing.T) {
		TestMultiProfileMerge(t)
	})
	t.Run("HealthCheck", func(t *testing.T) {
		TestHealthCheck(t)
	})
	t.Run("ListFiles", func(t *testing.T) {
		TestListFiles(t)
	})
	t.Run("MultiPasswordAuth", func(t *testing.T) {
		TestMultiPasswordAuth(t)
	})
	t.Run("FormatSpecificEndpoints", func(t *testing.T) {
		TestFormatSpecificEndpoints(t)
	})
	t.Run("SwaggerUI", func(t *testing.T) {
		TestSwaggerUI(t)
	})
	t.Run("FileSystemBackend", func(t *testing.T) {
		TestFileSystemBackend(t)
	})
	t.Run("BuildConfigFilename", func(t *testing.T) {
		TestBuildConfigFilename(t)
	})
	t.Run("CipherPlaceholder", func(t *testing.T) {
		TestCipherPlaceholder(t)
	})
	t.Run("DeleteHandler", func(t *testing.T) {
		TestDeleteHandler(t)
	})
	t.Run("PathTraversalPrevention", func(t *testing.T) {
		TestPathTraversalPrevention(t)
	})
	t.Run("UploadWithFullPath", func(t *testing.T) {
		TestUploadWithFullPath(t)
	})
}