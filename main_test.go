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

// TestResolveLabel verifies the resolveLabel function with the new behavior
// where user.DefaultLabel and globalDefaultLabel are applied WITHOUT requiring
// the useDefaultLabel query parameter.
func TestResolveLabel(t *testing.T) {
	tests := []struct {
		name          string
		labelFromPath string
		hasDefault    bool
		userDefault   string
		globalDefault string
		wantLabel     string
	}{
		{
			name:          "empty label with user default → use user default",
			labelFromPath: "",
			hasDefault:    true,
			userDefault:   "development",
			wantLabel:     "development",
		},
		{
			name:          "empty label with user default and no global default",
			labelFromPath: "",
			hasDefault:    true,
			userDefault:   "development",
			wantLabel:     "development",
		},
		{
			name:          "label from path takes priority over user default",
			labelFromPath: "production",
			hasDefault:    true,
			userDefault:   "development",
			wantLabel:     "production",
		},
		{
			name:          "non-empty label ignores user default",
			labelFromPath: "staging",
			hasDefault:    true,
			userDefault:   "development",
			wantLabel:     "staging",
		},
		{
			name:          "user default label custom value",
			labelFromPath: "",
			hasDefault:    true,
			userDefault:   "custom",
			wantLabel:     "custom",
		},
		{
			name:          "global default label used when no user default",
			labelFromPath: "",
			hasDefault:    false,
			globalDefault: "globaldev",
			wantLabel:     "globaldev",
		},
		{
			name:          "user default takes priority over global default",
			labelFromPath: "",
			hasDefault:    true,
			userDefault:   "prod",
			globalDefault: "globaldev",
			wantLabel:     "prod",
		},
		{
			name:          "no user or global default → hardcoded fallback",
			labelFromPath: "",
			hasDefault:    false,
			wantLabel:     "main",
		},
		{
			name:          "global default exists but user default overrides it",
			labelFromPath: "",
			hasDefault:    true,
			userDefault:   "prod",
			globalDefault: "globaldev",
			wantLabel:     "prod",
		},
		{
			name:          "empty user default falls back to global default",
			labelFromPath: "",
			hasDefault:    false,
			userDefault:   "",
			globalDefault: "globaldev",
			wantLabel:     "globaldev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var defaultLabel string
			if tt.hasDefault {
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

			req := httptest.NewRequest("GET", "/", nil)

			got := resolveLabel(tt.labelFromPath, req, user)
			if got != tt.wantLabel {
				t.Errorf("resolveLabel(%q, userDefault=%q, globalDefault=%q) = %q, want %q",
					tt.labelFromPath, user.DefaultLabel, globalDefaultLabel, got, tt.wantLabel)
			}
		})
	}
}

// TestResolveLabelQueryParamPresence verifies that the useDefaultLabel query
// parameter is no longer required — user/default labels are always applied
// regardless of the query parameter presence.
func TestResolveLabelQueryParamPresence(t *testing.T) {
	// With the new behavior, the useDefaultLabel param is NOT required.
	// The user default should be applied regardless of the param.
	user := &UserConfig{
		DefaultLabel: "production",
	}

	testCases := []struct {
		url      string
		expected string
	}{
		{"/?useDefaultLabel", "production"},
		{"/?useDefaultLabel=", "production"},
		{"/?useDefaultLabel=true", "production"},
		{"/?foo=bar", "production"},  // No useDefaultLabel param — but user default still applies
		{"/", "production"},           // No query param at all — user default still applies
	}

	for _, tc := range testCases {
		req := httptest.NewRequest("GET", tc.url, nil)
		user2 := *user
		got := resolveLabel("", req, &user2)
		if got != tc.expected {
			t.Errorf("URL=%q: resolveLabel() = %q, want %q", tc.url, got, tc.expected)
		}
	}
}

// TestResolveLabelUserHasNoDefaultLabel verifies the hardcoded fallback to "main"
// when the user has no DefaultLabel and no global default is set.
func TestResolveLabelUserHasNoDefaultLabel(t *testing.T) {
	user := &UserConfig{} // DefaultLabel is empty string

	setGlobalDefaultLabel(t, "")
	req := httptest.NewRequest("GET", "/", nil)
	got := resolveLabel("", req, user)
	if got != "main" {
		t.Errorf("resolveLabel() = %q, want main (hardcoded fallback, no user or global default)", got)
	}
}

// TestResolveLabelUserDefaultLabelEmptyButNoGlobalDefault verifies
// that an empty DefaultLabel with no global default falls back to "main".
func TestResolveLabelUserDefaultLabelEmptyButNoGlobalDefault(t *testing.T) {
	user := &UserConfig{
		DefaultLabel: "",
	}

	setGlobalDefaultLabel(t, "")
	req := httptest.NewRequest("GET", "/", nil)
	got := resolveLabel("", req, user)
	if got != "main" {
		t.Errorf("resolveLabel() = %q, want main (hardcoded fallback, empty user default)", got)
	}
}

// TestResolveLabelPathLabelAlwaysWins verifies that a label from the path
// always takes priority over user default and global default.
func TestResolveLabelPathLabelAlwaysWins(t *testing.T) {
	user := &UserConfig{
		DefaultLabel: "development",
	}

	setGlobalDefaultLabel(t, "globaldev")
	req := httptest.NewRequest("GET", "/", nil)
	got := resolveLabel("production", req, user)
	if got != "production" {
		t.Errorf("resolveLabel('production', ...) = %q, want 'production' (path label always wins)", got)
	}
}
