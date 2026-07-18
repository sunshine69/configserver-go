package lib

// ResolveLabel returns the list of label candidates to try for fetching config.
//
// When a label is explicitly provided, it returns only that label.
// When no label is specified (empty string), it returns ["main", "master"]
// so the server tries "main" first and falls back to "master" — matching
// Spring Cloud Config Server's default label fallback behavior.
func ResolveLabel(label string) []string {
	if label != "" {
		return []string{label}
	}
	return []string{"main", "master"}
}
