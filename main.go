package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	u "github.com/sunshine69/golang-tools/utils"
	"gopkg.in/yaml.v3"
)

// Configuration structures
type Config struct {
	Server        ServerConfig     `yaml:"server"`
	BackendConfig BackendConfigMap `yaml:"backend_config"`
}

type ServerConfig struct {
	Port  string `yaml:"port"`
	Users []User `yaml:"users"`
}

type User struct {
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	EncryptionKey string `yaml:"encryption_key"`
	Key           string `yaml:"key"`
	Cert          string `yaml:"cert"`
	Directory     string `yaml:"directory"`
	Backend       string `yaml:"backend"`
}

type BackendConfigMap struct {
	Filesystem FilesystemConfig `yaml:"filesystem"`
	Git        GitConfig        `yaml:"git"`
}

type FilesystemConfig struct {
	Directories []DirectoryConfig `yaml:"directories"`
}

type DirectoryConfig struct {
	Directory string `yaml:"directory"`
}

type GitConfig struct {
	URI          string `yaml:"uri"`
	SearchPaths  string `yaml:"search_paths"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	DefaultLabel string `yaml:"default_label"`
	CloneOnStart bool   `yaml:"clone_on_start"`
	LocalRepo    string `yaml:"local_repo"`
}

// Response structures
type ConfigResponse struct {
	Label           *string          `json:"label"`
	Name            string           `json:"name"`
	Profiles        []string         `json:"profiles"`
	PropertySources []PropertySource `json:"propertySources"`
	State           *string          `json:"state"`
	Version         *string          `json:"version"`
}

type PropertySource struct {
	Name   string                 `json:"name"`
	Source map[string]interface{} `json:"source"`
}

// Global variables
var config Config
var users map[string]*User

// Initialize configuration
func init() {
	loadConfig()
	users = make(map[string]*User)
	for i := range config.Server.Users {
		user := &config.Server.Users[i]
		users[user.Username] = user
	}
}

func loadConfig() {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Failed to read config.yaml:", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatal("Failed to parse config.yaml:", err)
	}
}

// Authentication middleware
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, exists := users[username]
		if !exists || user.Password != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Add user to request context
		r.Header.Set("X-User", username)
		next(w, r)
	}
}

// Get user from request
func getUserFromRequest(r *http.Request) *User {
	username := r.Header.Get("X-User")
	return users[username]
}

// Check if directory is allowed
func isDirectoryAllowed(userDir string) bool {
	for _, dirConfig := range config.BackendConfig.Filesystem.Directories {
		if strings.HasPrefix(userDir, dirConfig.Directory) {
			return true
		}
	}
	return false
}

// Encryption/Decryption functions
func encryptSymmetric(plaintext, key string) (string, error) {
	return u.Encrypt(plaintext, key)
}

func decryptSymmetric(ciphertext, key string) (string, error) {
	return u.Decrypt(ciphertext, key)
}

func encryptAsymmetric(plaintext string, certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	var pubKey *rsa.PublicKey
	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		pubKey = cert.PublicKey.(*rsa.PublicKey)
	} else {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", err
		}
		pubKey = pub.(*rsa.PublicKey)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(plaintext), nil)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAsymmetric(ciphertext string, keyPath string) (string, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to parse PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Process cipher patterns in content
func processCipherPatterns(content string, user *User) string {
	cipherPattern := regexp.MustCompile(`'\{cipher\}([^}']+)'`)

	return cipherPattern.ReplaceAllStringFunc(content, func(match string) string {
		cipherData := strings.TrimPrefix(match, "'{cipher}")
		cipherData = strings.TrimSuffix(cipherData, "'")
		var decrypted string
		var err error

		if user.EncryptionKey != "" {
			// Symmetric encryption
			decrypted, err = decryptSymmetric(cipherData, user.EncryptionKey)
		} else if user.Key != "" {
			// Asymmetric encryption
			decrypted, err = decryptAsymmetric(cipherData, user.Key)
		}

		if err != nil {
			return "<n/a>"
		}

		return decrypted
	})
}

// Flatten YAML to flat key-value pairs
func flattenYAML(data interface{}, prefix string, result map[string]interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newKey := key
			if prefix != "" {
				newKey = prefix + "." + key
			}
			flattenYAML(value, newKey, result)
		}
	case []interface{}:
		for i, value := range v {
			newKey := fmt.Sprintf("%s[%d]", prefix, i)
			flattenYAML(value, newKey, result)
		}
	default:
		result[prefix] = v
	}
}

// Git operations
func gitCheckout(repoPath, label string) error {
	if label == "" {
		label = config.BackendConfig.Git.DefaultLabel
	}

	cmd := exec.Command("git", "checkout", label)
	cmd.Dir = repoPath
	return cmd.Run()
}

// Handler functions
func encryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getUserFromRequest(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	plaintext := string(body)
	var encrypted string

	if user.EncryptionKey != "" {
		encrypted, err = encryptSymmetric(plaintext, user.EncryptionKey)
	} else if user.Cert != "" {
		encrypted, err = encryptAsymmetric(plaintext, user.Cert)
	} else {
		http.Error(w, "No encryption configuration found", http.StatusInternalServerError)
		return
	}

	if err != nil {
		http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, encrypted)
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getUserFromRequest(r)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	ciphertext := string(body)
	var decrypted string

	if user.EncryptionKey != "" {
		decrypted, err = decryptSymmetric(ciphertext, user.EncryptionKey)
	} else if user.Key != "" {
		decrypted, err = decryptAsymmetric(ciphertext, user.Key)
	} else {
		http.Error(w, "No decryption configuration found", http.StatusInternalServerError)
		return
	}

	if err != nil {
		http.Error(w, "Decryption failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, decrypted)
}

func configHandler(w http.ResponseWriter, r *http.Request) {
	user := getUserFromRequest(r)
	path := r.URL.Path

	// Check if path is an absolute file path
	if strings.HasPrefix(path, user.Directory) {
		if !isDirectoryAllowed(user.Directory) {
			http.Error(w, "Directory not allowed", http.StatusForbidden)
			return
		}

		serveFile(w, r, path, user)
		return
	}

	// Parse Spring Boot config server format: /{application}/{profile}/{label}/{path}
	parts := strings.Split(path, "/")
	println(u.JsonDump(parts, ""))
	if len(parts) < 3 {
		http.Error(w, "Invalid path format", http.StatusBadRequest)
		return
	}

	application := parts[1]
	profile := parts[2]
	var label string
	var filePath string

	if len(parts) >= 4 {
		label = parts[3]
	}
	if len(parts) >= 5 {
		filePath = strings.Join(parts[4:], "/")
	}

	if filePath != "" {
		// Serve specific file with format check
		serveSpecificFile(w, r, user, application, profile, label, filePath)
	} else {
		// Return JSON response
		serveConfigJSON(w, r, user, application, profile, label)
	}
}

func serveFile(w http.ResponseWriter, r *http.Request, filePath string, user *User) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	processedContent := processCipherPatterns(string(content), user)

	// Set appropriate content type
	ext := filepath.Ext(filePath)
	switch ext {
	case ".yaml", ".yml":
		w.Header().Set("Content-Type", "application/x-yaml")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".properties":
		w.Header().Set("Content-Type", "text/plain")
	default:
		w.Header().Set("Content-Type", "text/plain")
	}

	fmt.Fprint(w, processedContent)
}

func serveSpecificFile(w http.ResponseWriter, r *http.Request, user *User, application, profile, label, filePath string) {
	baseDir := user.Directory
	if user.Backend == "git" {
		baseDir = config.BackendConfig.Git.LocalRepo
		if label != "" {
			err := gitCheckout(baseDir, label)
			if err != nil {
				http.Error(w, "Failed to checkout git label", http.StatusInternalServerError)
				return
			}
		}
	}

	// Check for file with format {application}-{profile}-{label}.extension
	possibleFiles := []string{
		fmt.Sprintf("%s-%s-%s.yaml", application, profile, label),
		fmt.Sprintf("%s-%s-%s.yml", application, profile, label),
		fmt.Sprintf("%s-%s-%s.properties", application, profile, label),
		fmt.Sprintf("%s-%s-%s.json", application, profile, label),
		filePath,
	}

	for _, fileName := range possibleFiles {
		fullPath := filepath.Join(baseDir, fileName)
		if _, err := os.Stat(fullPath); err == nil {
			serveFile(w, r, fullPath, user)
			return
		}
	}

	http.Error(w, "Configuration file not found", http.StatusNotFound)
}

func serveConfigJSON(w http.ResponseWriter, r *http.Request, user *User, application, profile, label string) {
	baseDir := user.Directory
	if user.Backend == "git" {
		baseDir = config.BackendConfig.Git.LocalRepo
		if label != "" {
			err := gitCheckout(baseDir, label)
			if err != nil {
				http.Error(w, "Failed to checkout git label", http.StatusInternalServerError)
				return
			}
		}
	}

	response := ConfigResponse{
		Name:            application,
		Profiles:        []string{profile},
		PropertySources: []PropertySource{},
	}

	if label != "" {
		response.Label = &label
	}

	// Look for specific profile file
	possibleFiles := []string{
		fmt.Sprintf("%s-%s.yaml", application, profile),
		fmt.Sprintf("%s-%s.yml", application, profile),
		fmt.Sprintf("%s-%s.properties", application, profile),
		fmt.Sprintf("%s-%s.json", application, profile),
	}
	println(u.JsonDump(possibleFiles, ""))
	for _, fileName := range possibleFiles {
		fullPath := filepath.Join(baseDir, fileName)
		if content, err := os.ReadFile(fullPath); err == nil {
			processedContent := processCipherPatterns(string(content), user)
			source := parseConfigFile(processedContent, filepath.Ext(fileName))

			propertySource := PropertySource{
				Name:   "file://" + fullPath,
				Source: source,
			}
			response.PropertySources = append(response.PropertySources, propertySource)
			break
		}
	}

	// Look for application default file
	defaultFiles := []string{
		fmt.Sprintf("%s.yaml", application),
		fmt.Sprintf("%s.yml", application),
		fmt.Sprintf("%s.properties", application),
		fmt.Sprintf("%s.json", application),
	}

	for _, fileName := range defaultFiles {
		fullPath := filepath.Join(baseDir, fileName)
		if content, err := os.ReadFile(fullPath); err == nil {
			processedContent := processCipherPatterns(string(content), user)
			source := parseConfigFile(processedContent, filepath.Ext(fileName))

			propertySource := PropertySource{
				Name:   "file://" + fullPath,
				Source: source,
			}
			response.PropertySources = append(response.PropertySources, propertySource)
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func parseConfigFile(content, ext string) map[string]interface{} {
	result := make(map[string]interface{})

	switch ext {
	case ".yaml", ".yml":
		var data interface{}
		if err := yaml.Unmarshal([]byte(content), &data); err == nil {
			flattenYAML(data, "", result)
		}
	case ".json":
		var data interface{}
		if err := json.Unmarshal([]byte(content), &data); err == nil {
			flattenYAML(data, "", result)
		}
	case ".properties":
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return result
}

func main() {
	http.HandleFunc("/encrypt", basicAuth(encryptHandler))
	http.HandleFunc("/decrypt", basicAuth(decryptHandler))
	http.HandleFunc("/", basicAuth(configHandler))

	log.Printf("Config Server starting on port %s", config.Server.Port)
	log.Fatal(http.ListenAndServe(":"+config.Server.Port, nil))
}
