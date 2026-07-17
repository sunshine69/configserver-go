package lib

import (
	"os"
	"strings"
)

// PathServingConfig holds settings for the raw-file-by-path serving feature.
// When CONFIGSERVER_FILEPATH is set (e.g. "file:/opt/sonic/configuration"),
// any URL that starts with the configured path prefix is served as a raw file
// from the backend, using the remainder of the URL as the relative path.
type PathServingConfig struct {
	// Prefix is the URL prefix to match (e.g. "/opt/sonic/configuration").
	// Empty string means the feature is disabled.
	Prefix string
	// Enabled is true when the CONFIGSERVER_FILEPATH env var was set and
	// the prefix was successfully extracted.
	Enabled bool
}

// NewPathServingConfig reads CONFIGSERVER_FILEPATH and constructs the
// PathServingConfig. The env var value may be either:
//
//	file:/opt/sonic/configuration
//	/opt/sonic/configuration
//
// Both forms result in the same prefix "/opt/sonic/configuration".
func NewPathServingConfig() PathServingConfig {
	val := os.Getenv("CONFIGSERVER_FILEPATH")
	if val == "" {
		return PathServingConfig{}
	}

	// Strip the optional "file:" scheme prefix.
	clean := strings.TrimPrefix(val, "file:")
	clean = strings.TrimRight(clean, "/")

	return PathServingConfig{
		Prefix:  clean,
		Enabled: true,
	}
}

// MatchesPath reports whether the given URL path starts with the configured
// prefix and, if so, returns the relative path (the remainder after the
// prefix). Returns ("", false) when the feature is disabled or the path does
// not match.
func (c PathServingConfig) MatchesPath(urlPath string) (string, bool) {
	if !c.Enabled || c.Prefix == "" {
		return "", false
	}
	if !strings.HasPrefix(urlPath, c.Prefix) {
		return "", false
	}
	rel := strings.TrimPrefix(urlPath, c.Prefix)
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return "", false
	}
	return rel, true
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
