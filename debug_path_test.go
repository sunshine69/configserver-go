package main

import (
	"configservergo/backend"
	"configservergo/lib"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestPathServingDebug is a standalone test to debug path resolution logic.
// Run with: go test -v -run TestPathServingDebug .
func TestPathServingDebug(t *testing.T) {
	testCases := []struct {
		name     string
		urlPath  string
		pathsLen int
		paths    []string
	}{
		{
			name:     "/bruno/common/test/bruno/data.yaml",
			urlPath:  "/bruno/common/test/bruno/data.yaml",
			pathsLen: 4,
			paths:    []string{"bruno", "common", "test/bruno/data.yaml"},
		},
		{
			name:     "/bruno/common/test.yaml",
			urlPath:  "/bruno/common/test.yaml",
			pathsLen: 3,
			paths:    []string{"bruno", "common", "test.yaml"},
		},
		{
			name:     "/bruno/common/main",
			urlPath:  "/bruno/common/main",
			pathsLen: 3,
			paths:    []string{"bruno", "common", "main"},
		},
		{
			name:     "/bruno/common",
			urlPath:  "/bruno/common",
			pathsLen: 2,
			paths:    []string{"bruno", "common"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Printf("=== URL: %s ===\n", tc.urlPath)
			fmt.Printf("pathsLen: %d\n", tc.pathsLen)
			fmt.Printf("paths: %v\n", tc.paths)

			switch {
			case tc.pathsLen == 3:
				fmt.Println("==> pathsLen == 3 branch")
				label, ext := lib.SplitProfileAndExt(tc.paths[2])
				fmt.Printf("  label: '%s', ext: '%s'\n", label, ext)
				fmt.Printf("  contains '.': %v\n", strings.Contains(tc.paths[2], "."))
				if strings.Contains(tc.paths[2], ".") {
					filePath := strings.Join(tc.paths, "/")
					fmt.Printf("  filePath (BUG): %s\n", filePath)
					fmt.Printf("  filePath (CORRECT): %s\n", tc.paths[2])
				}
			case tc.pathsLen == 4:
				fmt.Println("==> pathsLen > 3 branch")
				filePath := strings.Join(tc.paths[2:], "/")
				fmt.Printf("  filePath: %s\n", filePath)
			}
			fmt.Println()
		})
	}
}

// TestGetValuesHandlerRouting traces which switch case is entered.
func TestGetValuesHandlerRouting(t *testing.T) {
	urls := []string{
		"/bruno/common",
		"/bruno/common/test.yaml",
		"/bruno/common/main",
		"/bruno/common/main/test/bruno/data.yaml",
		"/bruno/common/test/bruno/data.yaml",
		"/bruno/common/test/bruno/data.yml",
	}

	for _, url := range urls {
		paths := strings.Split(url, "/")[1:]
		pathsLen := len(paths)
		fmt.Printf("URL: %-55s pathsLen=%d paths=%v\n", url, pathsLen, paths)
	}

	// Simulate what the actual code does for pathsLen == 3
	t.Run("pathsLen 3 behavior", func(t *testing.T) {
		path := "/bruno/common/test.yaml"
		paths := strings.Split(path, "/")[1:]
		fmt.Printf("\nTest pathsLen==3: path=%s, paths=%v\n", path, paths)
		label, ext := lib.SplitProfileAndExt(paths[2])
		fmt.Printf("  SplitProfileAndExt: label='%s', ext='%s'\n", label, ext)
		fmt.Printf("  Has '.': %v\n", strings.Contains(paths[2], "."))
		if strings.Contains(paths[2], ".") {
			// BUG: this joins ALL segments including app and profile
			buggyPath := paths[0] + "/" + paths[1] + "/" + paths[2]
			correctPath := paths[2]
			fmt.Printf("  BUGGY filePath: %s\n", buggyPath)
			fmt.Printf("  CORRECT filePath: %s\n", correctPath)
		}
	})

	_ = http.StatusOK
	_ = backend.ErrNotExist
}
