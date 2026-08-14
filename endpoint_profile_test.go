package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"configservergo/backend"
)

// setupTest creates a temporary filesystem backend with test config files
// and returns a configured App with a test user, plus a cleanup function.
func setupTest(t *testing.T, files map[string]string) (*App, string) {
	t.Helper()
	tmpDir := t.TempDir()
	be := backend.NewFileSystemBackend(tmpDir)

	// Create test files
	for path, content := range files {
		fullPath := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create directory for %s: %v", path, err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", path, err)
		}
	}

	testUser := &UserConfig{
		Username: "testuser",
		Password: "changeme",
		Backend:  "filesystem",
	}

	app := &App{
		Users:   map[string]*UserConfig{"testuser": testUser},
		Backend: backend.NewResolver(be, nil),
	}

	return app, tmpDir
}

// parseGetValuesResponse parses a JSON GetValuesResponse from an httptest.ResponseRecorder.
func parseGetValuesResponse(t *testing.T, rr *httptest.ResponseRecorder) *GetValuesResponse {
	t.Helper()
	var resp GetValuesResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse GetValuesResponse: %v", err)
	}
	return &resp
}

// TestServeValuesNoProfileReturnsDefault verifies that GET /myapp returns JSON with "default" profile.
//
// Before fix: Returns raw file (404) or empty propertySources
// After fix: Returns JSON with "default" profile in profiles list
func TestServeValuesNoProfileReturnsDefault(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"myapp-default.yaml": "key1: value-from-default",
	})

	// Create request
	req := httptest.NewRequest("GET", "/myapp", nil)
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	// Call handler
	app.getValuesHandler(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseGetValuesResponse(t, rr)

	// Verify profiles include "default"
	if len(resp.Profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d: %v", len(resp.Profiles), resp.Profiles)
	}
	if resp.Profiles[0] != "default" {
		t.Fatalf("expected profile 'default', got %q", resp.Profiles[0])
	}
	// Verify property source contains the default value
	if len(resp.PropertySources) != 1 {
		t.Fatalf("expected 1 property source, got %d", len(resp.PropertySources))
	}
	if val, ok := resp.PropertySources[0].Source["key1"]; !ok || val != "value-from-default" {
		t.Fatalf("expected key1=value-from-default, got %v", val)
	}
}

// TestServeValuesProfileIncludesDefault verifies that GET /myapp/prod includes both
// "default" and "prod" profiles, with default values overridden by prod values.
//
// Before fix: Profiles: ["prod"], only reads myapp-prod.yaml
// After fix: Profiles: ["default", "prod"], reads both and merges
func TestServeValuesProfileIncludesDefault(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"myapp-default.yaml": "key1: value-from-default\nkey2: only-in-default",
		"myapp-prod.yaml":    "key1: value-from-prod\nkey3: only-in-prod",
	})

	// Create request
	req := httptest.NewRequest("GET", "/myapp/prod", nil)
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	app.getValuesHandler(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseGetValuesResponse(t, rr)

	// Verify profiles include BOTH default and prod
	if len(resp.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(resp.Profiles), resp.Profiles)
	}
	if resp.Profiles[0] != "default" {
		t.Fatalf("expected first profile to be 'default', got %q", resp.Profiles[0])
	}
	if resp.Profiles[1] != "prod" {
		t.Fatalf("expected second profile to be 'prod', got %q", resp.Profiles[1])
	}

	// Verify property sources
	if len(resp.PropertySources) != 2 {
		t.Fatalf("expected 2 property sources, got %d", len(resp.PropertySources))
	}

	// Verify default value is overridden by prod value
	defaultValues := resp.PropertySources[0].Source
	if val, ok := defaultValues["key1"]; !ok || val != "value-from-default" {
		t.Fatalf("default key1 should be 'value-from-default', got %v", val)
	}
	if val, ok := defaultValues["key2"]; !ok || val != "only-in-default" {
		t.Fatalf("default key2 should be 'only-in-default', got %v", val)
	}

	prodValues := resp.PropertySources[1].Source
	if val, ok := prodValues["key1"]; !ok || val != "value-from-prod" {
		t.Fatalf("prod key1 should be 'value-from-prod', got %v", val)
	}
	if val, ok := prodValues["key3"]; !ok || val != "only-in-prod" {
		t.Fatalf("prod key3 should be 'only-in-prod', got %v", val)
	}
}

// TestServeValuesDefaultNotDuplicated verifies that if "default" is already in the
// requested profiles, it's NOT duplicated.
//
// Example: GET /myapp/default,prod
func TestServeValuesDefaultNotDuplicated(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"myapp-default.yaml": "key1: value-from-default",
		"myapp-prod.yaml":    "key1: value-from-prod",
	})

	// Create request with both profiles
	req := httptest.NewRequest("GET", "/myapp/default,prod", nil)
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	app.getValuesHandler(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseGetValuesResponse(t, rr)

	// Verify profiles include BOTH default and prod, no duplication
	if len(resp.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(resp.Profiles), resp.Profiles)
	}
	if resp.Profiles[0] != "default" || resp.Profiles[1] != "prod" {
		t.Fatalf("expected profiles ['default', 'prod'], got %v", resp.Profiles)
	}

	// Verify default is read first (property source order)
	if len(resp.PropertySources) != 2 {
		t.Fatalf("expected 2 property sources, got %d", len(resp.PropertySources))
	}
	// Default should have its value, prod should override key1
	if val := resp.PropertySources[0].Source["key1"]; val != "value-from-default" {
		t.Fatalf("default key1 should be 'value-from-default', got %v", val)
	}
	if val := resp.PropertySources[1].Source["key1"]; val != "value-from-prod" {
		t.Fatalf("prod key1 should be 'value-from-prod', got %v", val)
	}
}

// TestServeValuesHyphenatedPathIncludesDefault verifies that GET /myapp-prod
// also gets default profile merged (not just prod).
//
// Before fix: Profiles: ["prod"], only reads myapp-prod.yaml
// After fix: Profiles: ["default", "prod"], reads both
func TestServeValuesHyphenatedPathIncludesDefault(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"myapp-default.yaml": "key1: value-from-default",
		"myapp-prod.yaml":    "key1: value-from-prod",
	})

	// Create request with hyphenated path (Spring Cloud Config raw file style)
	req := httptest.NewRequest("GET", "/myapp-prod", nil)
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	app.getValuesHandler(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseGetValuesResponse(t, rr)

	// Verify profiles include BOTH default and prod
	if len(resp.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(resp.Profiles), resp.Profiles)
	}
	if resp.Profiles[0] != "default" {
		t.Fatalf("expected first profile to be 'default', got %q", resp.Profiles[0])
	}
	if resp.Profiles[1] != "prod" {
		t.Fatalf("expected second profile to be 'prod', got %q", resp.Profiles[1])
	}
}

// TestServeValuesMultipleProfilesIncludesDefault verifies that when multiple
// profiles are specified (comma-separated), "default" is prepended.
//
// Example: GET /myapp/prod,common
//
// Before fix: Profiles: ["prod", "common"], only reads those two
// After fix: Profiles: ["default", "prod", "common"], reads all three
func TestServeValuesMultipleProfilesIncludesDefault(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"myapp-default.yaml": "key1: default-value",
		"myapp-prod.yaml":    "key1: prod-value",
		"myapp-common.yaml":  "key1: common-value",
	})

	// Create request with multiple profiles
	req := httptest.NewRequest("GET", "/myapp/prod,common", nil)
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	app.getValuesHandler(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseGetValuesResponse(t, rr)

	// Verify profiles include ALL three: default + prod + common
	if len(resp.Profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d: %v", len(resp.Profiles), resp.Profiles)
	}
	if resp.Profiles[0] != "default" {
		t.Fatalf("expected first profile to be 'default', got %q", resp.Profiles[0])
	}
	if resp.Profiles[1] != "prod" {
		t.Fatalf("expected second profile to be 'prod', got %q", resp.Profiles[1])
	}
	if resp.Profiles[2] != "common" {
		t.Fatalf("expected third profile to be 'common', got %q", resp.Profiles[2])
	}
}

// TestServeValuesRawFileStillWorks verifies that raw file endpoints still work
// (Accept: application/octet-stream).
//
// Example: GET /myapp/prod.yaml
//
// This should NOT be affected by the profile merging change.
func TestServeValuesRawFileStillWorks(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"myapp-prod.yaml": "key1: value-from-prod",
	})

	// Create request with Accept: application/octet-stream and extension
	req := httptest.NewRequest("GET", "/myapp/prod.yaml", nil)
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	app.getValuesHandler(rr, req)

	// Verify raw file is returned
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Should return raw YAML content, not JSON
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/octet-stream" {
		t.Fatalf("expected Content-Type application/octet-stream, got %q", contentType)
	}

	// Should be raw YAML content, not JSON
	if bytes.Contains(rr.Body.Bytes(), []byte("propertySources")) {
		t.Fatalf("raw file endpoint returned JSON instead of raw content")
	}
}

// TestServeValuesApplicationProfileMerging verifies that application.yaml and
// application-prod.yaml are also read in the profile merging.
//
// Before fix: Only reads myapp-prod.yaml, myapp.yaml
// After fix: Also reads application.yaml (lowest), application-prod.yaml
func TestServeValuesApplicationProfileMerging(t *testing.T) {
	app, _ := setupTest(t, map[string]string{
		"application.yaml":       "app.key1: from-application\napp.key2: from-application",
		"application-prod.yaml":  "app.key2: from-application-prod",
		"myapp-default.yaml":     "myapp.key1: from-myapp-default",
		"myapp-prod.yaml":        "myapp.key2: from-myapp-prod",
	})

	// Create request
	req := httptest.NewRequest("GET", "/myapp/prod", nil)
	req.Header.Set("X-Username", "testuser")
	rr := httptest.NewRecorder()

	app.getValuesHandler(rr, req)

	// Verify response
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	resp := parseGetValuesResponse(t, rr)

	// Verify profiles include both default and prod
	if len(resp.Profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(resp.Profiles), resp.Profiles)
	}

	// Verify property sources include application.yaml, myapp-default.yaml, myapp-prod.yaml
	// application-prod.yaml should also be read (this is the new behavior from default profile)
	if len(resp.PropertySources) < 4 {
		t.Fatalf("expected at least 4 property sources, got %d", len(resp.PropertySources))
	}

	// Verify the sources include application-level and myapp-level configs
	hasApplication := false
	hasApplicationProd := false
	hasMyappDefault := false
	hasMyappProd := false
	for _, ps := range resp.PropertySources {
		if len(ps.Source) > 0 {
			// Check source names to identify which config was read
			if !hasApplication && ps.Source["app.key2"] == "from-application" {
				hasApplication = true
			}
			if !hasApplicationProd && ps.Source["app.key2"] == "from-application-prod" {
				hasApplicationProd = true
			}
			if !hasMyappDefault && ps.Source["myapp.key1"] == "from-myapp-default" {
				hasMyappDefault = true
			}
			if !hasMyappProd && ps.Source["myapp.key2"] == "from-myapp-prod" {
				hasMyappProd = true
			}
		}
	}

	if !hasApplication {
		t.Fatalf("missing application.yaml property source")
	}
	if !hasMyappDefault {
		t.Fatalf("missing myapp-default.yaml property source")
	}
	if !hasMyappProd {
		t.Fatalf("missing myapp-prod.yaml property source")
	}
	// application-prod.yaml should be read because default profile now includes it
	if !hasApplicationProd {
		t.Fatalf("missing application-prod.yaml property source")
	}
}
