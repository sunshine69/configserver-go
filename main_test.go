package main

import (
	"net/http/httptest"
	"testing"
)

// setGlobalDefaultLabel sets the package-level globalDefaultLabel for testing.
// It restores the previous value in a defer so tests don't interfere with each other.
func setGlobalDefaultLabel(t *testing.T, val string) {
	t.Helper()
	old := globalDefaultLabel
	globalDefaultLabel = val
	t.Cleanup(func() {
		globalDefaultLabel = old
	})
}

func TestResolveLabel(t *testing.T) {
	tests := []struct {
		name          string
		labelFromPath string
		hasDefault    bool
		useDefault    bool
		userDefault   string
		globalDefault string
		wantLabel     string
	}{
		{
			name:          "empty label no useDefaultLabel param",
			labelFromPath: "",
			hasDefault:    true,
			useDefault:    false,
			wantLabel:     "main",
		},
		{
			name:          "empty label with useDefaultLabel param but no user or global default",
			labelFromPath: "",
			hasDefault:    false,
			useDefault:    true,
			wantLabel:     "main",
		},
		{
			name:          "empty label with useDefaultLabel param and user default",
			labelFromPath: "",
			hasDefault:    true,
			useDefault:    true,
			wantLabel:     "development",
		},
		{
			name:          "label from path takes priority",
			labelFromPath: "production",
			hasDefault:    true,
			useDefault:    true,
			wantLabel:     "production",
		},
		{
			name:          "non-empty label ignores useDefaultLabel",
			labelFromPath: "staging",
			hasDefault:    true,
			useDefault:    true,
			wantLabel:     "staging",
		},
		{
			name:          "user default label is development by default",
			labelFromPath: "",
			hasDefault:    true,
			useDefault:    true,
			wantLabel:     "development",
		},
		{
			name:          "user default label custom value",
			labelFromPath: "",
			hasDefault:    true,
			useDefault:    true,
			userDefault:   "custom",
			wantLabel:     "custom",
		},
		{
			name:          "global default label used when no user default",
			labelFromPath: "",
			hasDefault:    false,
			useDefault:    true,
			globalDefault: "globaldev",
			wantLabel:     "globaldev",
		},
		{
			name:          "user default takes priority over global default",
			labelFromPath: "",
			hasDefault:    true,
			useDefault:    true,
			userDefault:   "prod",
			globalDefault: "globaldev",
			wantLabel:     "prod",
		},
		{
			name:          "no useDefaultLabel param and no user default → hardcoded fallback",
			labelFromPath: "",
			hasDefault:    false,
			useDefault:    false,
			globalDefault: "globaldev",
			wantLabel:     "main",
		},
		{
			name:          "global default with no user default and no param → hardcoded fallback",
			labelFromPath: "",
			hasDefault:    false,
			useDefault:    false,
			globalDefault: "globaldev",
			wantLabel:     "main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var defaultLabel string
			if tt.hasDefault {
				defaultLabel = "development"
			}
			if tt.userDefault != "" {
				defaultLabel = tt.userDefault
			}
			user := &UserConfig{
				DefaultLabel: defaultLabel,
			}

			// Set global default if the test case specifies one
			if tt.globalDefault != "" {
				setGlobalDefaultLabel(t, tt.globalDefault)
			} else {
				setGlobalDefaultLabel(t, "")
			}

			reqURL := "/"
			if tt.useDefault {
				reqURL = "/?useDefaultLabel"
			}
			req := httptest.NewRequest("GET", reqURL, nil)

			got := resolveLabel(tt.labelFromPath, req, user)
			if got != tt.wantLabel {
				t.Errorf("resolveLabel(%q, useDefault=%v, userDefault=%q, globalDefault=%q) = %q, want %q",
					tt.labelFromPath, tt.useDefault, user.DefaultLabel, globalDefaultLabel, got, tt.wantLabel)
			}
		})
	}
}

func TestResolveLabelQueryParamPresence(t *testing.T) {
	// The useDefaultLabel param can be present without a value
	// (e.g., ?useDefaultLabel or ?useDefaultLabel=)
	// r.URL.Query().Has("useDefaultLabel") should return true for both cases
	user := &UserConfig{
		DefaultLabel: "production",
	}

	testCases := []struct {
		url     string
		wantUse bool
	}{
		{"/?useDefaultLabel", true},
		{"/?useDefaultLabel=", true},
		{"/?useDefaultLabel=true", true},
		{"/?foo=bar", false},
		{"/", false},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", tc.url, nil)
		user2 := *user
		got := resolveLabel("", req, &user2)
		expected := "main"
		if tc.wantUse {
			expected = "production"
		}
		if got != expected {
			t.Errorf("URL=%q: resolveLabel() = %q, want %q", tc.url, got, expected)
		}
	}
}

func TestResolveLabelUserHasNoDefaultLabel(t *testing.T) {
	// When user has no DefaultLabel and no global default,
	// final fallback is "main"
	user := &UserConfig{} // DefaultLabel is empty string

	setGlobalDefaultLabel(t, "")
	req := httptest.NewRequest("GET", "/?useDefaultLabel", nil)
	got := resolveLabel("", req, user)
	if got != "main" {
		t.Errorf("resolveLabel() = %q, want main (hardcoded fallback, no user or global default)", got)
	}
}

func TestResolveLabelUserDefaultLabelEmptyButParamPresent(t *testing.T) {
	// Even with empty DefaultLabel, final fallback is "main"
	user := &UserConfig{
		DefaultLabel: "",
	}

	setGlobalDefaultLabel(t, "")
	req := httptest.NewRequest("GET", "/?useDefaultLabel", nil)
	got := resolveLabel("", req, user)
	if got != "main" {
		t.Errorf("resolveLabel() = %q, want main (hardcoded fallback, empty user default)", got)
	}
}
