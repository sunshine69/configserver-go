package lib

import (
	"configservergo/backend"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var SupportedConfigFileType = []string{".properties", ".yml", ".yaml", ".json"}

// ParseUploadFilename parses a filename like "myapp-prod-staging.yaml" or
// "myapp-prod.yaml" into (app, profile, label).
func ParseUploadFilename(filename string) (app, profile, label string) {
	// Remove extension
	name := strings.TrimSuffix(filename, filepath.Ext(filename))

	// Find the last hyphen to split profile from label
	lastHyphen := strings.LastIndex(name, "-")
	if lastHyphen == -1 {
		// No hyphen: treat entire name as app, no profile
		return name, "", ""
	}

	// Everything before the last hyphen is app
	app = name[:lastHyphen]
	// The part after the last hyphen contains profile[-label]
	rest := name[lastHyphen+1:]

	// Split rest into profile and optional label
	restParts := strings.Split(rest, "-")
	if len(restParts) >= 2 {
		// profile-label: restParts[0] is profile, restParts[1:] joined is label
		return app, restParts[0], strings.Join(restParts[1:], "-")
	}
	// profile only
	return app, rest, ""
}

// ValidConfigPathSegment validates that a string contains only safe characters
// for use in config paths (alphanumeric, hyphens, underscores).
func ValidConfigPathSegment(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// SupportedFileExtension checks if the extension is one of the supported config
// file types.
func SupportedFileExtension(ext string) bool {
	for _, supported := range SupportedConfigFileType {
		if ext == supported {
			return true
		}
	}
	return false
}

// ParseProfiles splits a comma-separated profile string into individual profiles.
// Examples: "dev" → ["dev"], "dev,common,production" → ["dev", "common", "production"]
func ParseProfiles(profilesStr string) []string {
	profiles := strings.Split(profilesStr, ",")
	result := make([]string, 0, len(profiles))
	for _, p := range profiles {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// DetermineSourceName returns a descriptive name for a property source based on
// the backend type. This matches Spring Cloud Config's naming convention where
// the backend type is included in the source name.
func DetermineSourceName(be backend.Backend, app, profile, label, ext string) string {
	// Check if it's a filesystem backend
	if _, ok := be.(*backend.FileSystemBackend); ok {
		return fmt.Sprintf("FileSystemBackend app=%s profile=%s label=%s ext=%s", app, profile, label, ext)
	}
	// Default to postgres naming
	return fmt.Sprintf("postgres:config_server_files app=%s profile=%s label=%s ext=%s", app, profile, label, ext)
}

// SplitProfileAndExt splits a string like "dev.yaml" into ("dev", ".yaml"), or
// "dev" into ("dev", ""). It is used by the GET handler to separate the profile
// name from its file extension.
func SplitProfileAndExt(s string) (profile, ext string) {
	ext = filepath.Ext(s)
	profile = strings.TrimSuffix(s, ext)
	if ext == "" {
		return s, ""
	}
	return profile, ext
}

// ParseConfigData parses raw config content into a flat key-value map.
func ParseConfigData(content, ext string) map[string]interface{} {
	result := make(map[string]interface{})

	switch ext {
	case ".yaml", ".yml":
		var data interface{}
		if err := yaml.Unmarshal([]byte(content), &data); err == nil {
			FlatternDataToMap(data, "", result)
		}
	case ".json":
		var data interface{}
		if err := json.Unmarshal([]byte(content), &data); err == nil {
			FlatternDataToMap(data, "", result)
		}
	case ".properties":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return result
}

// FlatternDataToMap flattens nested YAML/JSON into dot-notation keys.
func FlatternDataToMap(data interface{}, prefix string, result map[string]interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newKey := key
			if prefix != "" {
				newKey = prefix + "." + key
			}
			FlatternDataToMap(value, newKey, result)
		}
	case []interface{}:
		for i, value := range v {
			newKey := fmt.Sprintf("%s[%d]", prefix, i)
			FlatternDataToMap(value, newKey, result)
		}
	default:
		result[prefix] = v
	}
}

var CipherPattern = regexp.MustCompile(`[']{0,1}\{cipher\}[^}']+[']{0,1}`)
var PlaceholderPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// ResolvePlaceholders replaces ${VAR} placeholders with environment variable values.
// If the environment variable is not set, returns the placeholder as-is.
func ResolvePlaceholders(content string) string {
	return PlaceholderPattern.ReplaceAllStringFunc(content, func(match string) string {
		varName := match[2 : len(match)-1] // Extract variable name between ${ and }
		value := os.Getenv(varName)
		if value != "" {
			return value
		}
		return match // Keep placeholder if env var not set
	})
}
