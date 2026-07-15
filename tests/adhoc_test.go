package tests

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	u "github.com/sunshine69/golang-tools/utils"
)

func TestSliceIndexing(t *testing.T) {
	path := "/app1/prof1/label1/home/user/config/config.yaml"
	// path := "/home/user/config/config.yaml"
	paths := strings.Split(path, "/")[1:]
	paths_len := len(paths)
	requestFileName := paths[paths_len-1]
	dir := "/home/user/config"
	fullpath := filepath.Join(dir, requestFileName)
	prefix_paths := strings.TrimSuffix(path, fullpath)

	fmt.Println(u.JsonDump(prefix_paths, ""))
	fmt.Println(requestFileName)
}
