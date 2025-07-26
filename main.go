package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
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

type Config struct {
	Server struct {
		Port    string `yaml:"port"`
		Users   []User `yaml:"users"`
		Backend string `yaml:"backend"` // "filesystem" or "git"
	} `yaml:"server"`
	Backend BackendConfig `yaml:"backend_config"`
}

type User struct {
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	EncryptionKey string `yaml:"encryption_key,omitempty"` // base64 encoded key for symmetric
	Key           string `yaml:"key,omitempty"`            // path to private key for asymmetric
	Cert          string `yaml:"cert,omitempty"`           // path to public key/cert for asymmetric
}

type BackendConfig struct {
	Filesystem *FilesystemConfig `yaml:"filesystem,omitempty"`
	Git        *GitConfig        `yaml:"git,omitempty"`
}

type FilesystemConfig struct {
	Directories []DirectoryConfig `yaml:"directories"`
}

type GitConfig struct {
	URI          string `yaml:"uri"`
	SearchPaths  string `yaml:"search_paths"`            // comma-separated paths
	Username     string `yaml:"username,omitempty"`      // git username
	Password     string `yaml:"password,omitempty"`      // git password/token
	DefaultLabel string `yaml:"default_label,omitempty"` // default branch/tag
	CloneOnStart bool   `yaml:"clone_on_start,omitempty"`
	LocalRepo    string `yaml:"local_repo,omitempty"` // local clone path
}

type DirectoryConfig struct {
	Directory string `yaml:"directory"`
}

// Backend interface for different config sources
type Backend interface {
	GetFile(path, application, profile, label string) ([]byte, error)
	ListFiles(path string) ([]string, error)
	Initialize() error
}

type ConfigServer struct {
	config      *Config
	backend     Backend
	users       map[string]*User
	userRSAKeys map[string]*UserRSAKeys // Cache for user RSA keys
	cipherRegex *regexp.Regexp
}

type UserRSAKeys struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

type EncryptRequest struct {
	Data string `json:"data"`
}

type EncryptResponse struct {
	Data string `json:"data"`
}

type DecryptRequest struct {
	Data string `json:"data"`
}

type DecryptResponse struct {
	Data string `json:"data"`
}

// Filesystem Backend Implementation
type FilesystemBackend struct {
	directories []string
}

func NewFilesystemBackend(config BackendConfig) *FilesystemBackend {
	var dirs []string
	if config.Filesystem != nil {
		for _, dir := range config.Filesystem.Directories {
			dirs = append(dirs, dir.Directory)
		}
	}
	return &FilesystemBackend{directories: dirs}
}

func (fb *FilesystemBackend) Initialize() error {
	for _, dir := range fb.directories {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("directory does not exist: %s", dir)
		}
	}
	return nil
}

func (fb *FilesystemBackend) isDirectoryAllowed(dirPath string) bool {
	for _, allowedDir := range fb.directories {
		if dirPath == allowedDir {
			return true
		}
	}
	return false
}

func (fb *FilesystemBackend) GetFile(path, application, profile, label string) ([]byte, error) {
	// For filesystem, we use the path directly
	fullPath := "/" + strings.TrimPrefix(path, "/")
	dirPath := filepath.Dir(fullPath)

	if !fb.isDirectoryAllowed(dirPath) {
		return nil, fmt.Errorf("directory not allowed: %s", dirPath)
	}

	return os.ReadFile(fullPath)
}

func (fb *FilesystemBackend) ListFiles(path string) ([]string, error) {
	fullPath := "/" + strings.TrimPrefix(path, "/")
	dirPath := filepath.Dir(fullPath)

	if !fb.isDirectoryAllowed(dirPath) {
		return nil, fmt.Errorf("directory not allowed: %s", dirPath)
	}

	files, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}

	var fileNames []string
	for _, file := range files {
		fileNames = append(fileNames, file.Name())
	}
	return fileNames, nil
}

// Git Backend Implementation
type GitBackend struct {
	uri          string
	searchPaths  []string
	username     string
	password     string
	defaultLabel string
	localRepo    string
}

func NewGitBackend(config BackendConfig) *GitBackend {
	if config.Git == nil {
		return nil
	}

	gitConfig := config.Git
	searchPaths := []string{"/"}
	if gitConfig.SearchPaths != "" {
		searchPaths = strings.Split(gitConfig.SearchPaths, ",")
		for i, path := range searchPaths {
			searchPaths[i] = strings.TrimSpace(path)
		}
	}

	defaultLabel := "main"
	if gitConfig.DefaultLabel != "" {
		defaultLabel = gitConfig.DefaultLabel
	}

	localRepo := gitConfig.LocalRepo
	if localRepo == "" {
		localRepo = "./git-repo"
	}

	return &GitBackend{
		uri:          gitConfig.URI,
		searchPaths:  searchPaths,
		username:     gitConfig.Username,
		password:     gitConfig.Password,
		defaultLabel: defaultLabel,
		localRepo:    localRepo,
	}
}

func (gb *GitBackend) Initialize() error {
	if gb.uri == "" {
		return fmt.Errorf("git URI is required")
	}

	// Clone or update repository
	if _, err := os.Stat(gb.localRepo); os.IsNotExist(err) {
		return gb.cloneRepo()
	} else {
		return gb.pullRepo()
	}
}

func (gb *GitBackend) cloneRepo() error {
	cmd := exec.Command("git", "clone", gb.uri, gb.localRepo)
	if gb.username != "" && gb.password != "" {
		// For HTTPS with auth, modify the URL
		authURL := strings.Replace(gb.uri, "https://", fmt.Sprintf("https://%s:%s@", gb.username, gb.password), 1)
		cmd = exec.Command("git", "clone", authURL, gb.localRepo)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to clone repo: %v, output: %s", err, output)
	}
	return nil
}

func (gb *GitBackend) pullRepo() error {
	cmd := exec.Command("git", "-C", gb.localRepo, "pull")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to pull repo: %v, output: %s", err, output)
	}
	return nil
}

func (gb *GitBackend) checkoutLabel(label string) error {
	if label == "" {
		label = gb.defaultLabel
	}

	cmd := exec.Command("git", "-C", gb.localRepo, "checkout", label)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to checkout %s: %v, output: %s", label, err, output)
	}
	return nil
}

// Parse Spring Cloud Config path: /{application}/{profile}/{label}/{path}
// or /{application}-{profile}.{extension} format
func (gb *GitBackend) parsePath(requestPath string) (application, profile, label, filePath string) {
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")

	if len(parts) >= 4 {
		// Format: /{application}/{profile}/{label}/{path...}
		application = parts[0]
		profile = parts[1]
		label = parts[2]
		filePath = strings.Join(parts[3:], "/")
	} else if len(parts) >= 3 {
		// Format: /{application}/{profile}/{path...}
		application = parts[0]
		profile = parts[1]
		label = gb.defaultLabel
		filePath = strings.Join(parts[2:], "/")
	} else if len(parts) == 1 {
		// Try to parse application-profile.extension format
		filename := parts[0]
		if strings.Contains(filename, "-") && strings.Contains(filename, ".") {
			nameExt := strings.Split(filename, ".")
			appProfile := strings.Split(nameExt[0], "-")
			if len(appProfile) >= 2 {
				application = appProfile[0]
				profile = strings.Join(appProfile[1:], "-")
				label = gb.defaultLabel
				filePath = filename
			}
		} else {
			application = "application"
			profile = "default"
			label = gb.defaultLabel
			filePath = filename
		}
	}

	return
}

func (gb *GitBackend) GetFile(path, application, profile, label string) ([]byte, error) {
	// Parse the request path if application, profile, label are not provided
	if application == "" {
		application, profile, label, path = gb.parsePath(path)
	}

	// Ensure we're on the right branch/tag
	if err := gb.checkoutLabel(label); err != nil {
		return nil, err
	}

	// Search in configured paths
	for _, searchPath := range gb.searchPaths {
		fullPath := filepath.Join(gb.localRepo, searchPath, path)
		if content, err := os.ReadFile(fullPath); err == nil {
			return content, nil
		}

		// Try with application-profile.extension format
		if application != "" && profile != "" {
			ext := filepath.Ext(path)
			if ext == "" {
				ext = ".yml" // default extension
			}
			filename := fmt.Sprintf("%s-%s%s", application, profile, ext)
			fullPath = filepath.Join(gb.localRepo, searchPath, filename)
			if content, err := os.ReadFile(fullPath); err == nil {
				return content, nil
			}
		}
	}

	return nil, fmt.Errorf("file not found: %s", path)
}

func (gb *GitBackend) ListFiles(path string) ([]string, error) {
	application, profile, label, dirPath := gb.parsePath(path)

	if err := gb.checkoutLabel(label); err != nil {
		return nil, err
	}

	for _, searchPath := range gb.searchPaths {
		fullPath := filepath.Join(gb.localRepo, searchPath, dirPath)
		if files, err := os.ReadDir(fullPath); err == nil {
			var fileNames []string
			for _, file := range files {
				fileNames = append(fileNames, file.Name())
			}
			return fileNames, nil
		}
	}

	return nil, fmt.Errorf("directory not found: %s (app: %s, profile: %s, label: %s)", path, application, profile, label)
}

func LoadConfig(configFile string) (*Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Set defaults
	if config.Server.Port == "" {
		config.Server.Port = "8888"
	}
	if config.Server.Backend == "" {
		config.Server.Backend = "filesystem"
	}

	return &config, nil
}

func NewConfigServer(config *Config) (*ConfigServer, error) {
	cs := &ConfigServer{
		config:      config,
		users:       make(map[string]*User),
		userRSAKeys: make(map[string]*UserRSAKeys),
		cipherRegex: regexp.MustCompile(`'\{cipher\}([A-Za-z0-9+/=]+)'`),
	}

	// Index users by username and load RSA keys for asymmetric users
	for i := range config.Server.Users {
		user := &config.Server.Users[i]
		cs.users[user.Username] = user

		// If no encryption_key, load RSA keys for asymmetric encryption
		if user.EncryptionKey == "" {
			if user.Key == "" || user.Cert == "" {
				return nil, fmt.Errorf("user %s: key and cert paths required for asymmetric encryption", user.Username)
			}

			rsaKeys, err := cs.loadUserRSAKeys(user)
			if err != nil {
				return nil, fmt.Errorf("failed to load RSA keys for user %s: %v", user.Username, err)
			}
			cs.userRSAKeys[user.Username] = rsaKeys
		}
	}

	// Initialize backend
	var err error
	switch config.Server.Backend {
	case "filesystem":
		cs.backend = NewFilesystemBackend(config.Backend)
	case "git":
		cs.backend = NewGitBackend(config.Backend)
		if cs.backend == nil {
			return nil, fmt.Errorf("git backend configuration is missing")
		}
	default:
		return nil, fmt.Errorf("unsupported backend: %s", config.Server.Backend)
	}

	if err = cs.backend.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize backend: %v", err)
	}

	return cs, nil
}

// Load RSA keys for a user
func (cs *ConfigServer) loadUserRSAKeys(user *User) (*UserRSAKeys, error) {
	// Load private key
	privKeyData, err := os.ReadFile(user.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	privKeyBlock, _ := pem.Decode(privKeyData)
	if privKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		privKeyInterface, err := x509.ParsePKCS8PrivateKey(privKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		var ok bool
		privKey, ok = privKeyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	// Load public key/certificate
	pubKeyData, err := os.ReadFile(user.Cert)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key/cert: %v", err)
	}

	pubKeyBlock, _ := pem.Decode(pubKeyData)
	if pubKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode public key/cert PEM")
	}

	var pubKey *rsa.PublicKey
	if pubKeyBlock.Type == "CERTIFICATE" {
		// Parse as certificate
		cert, err := x509.ParseCertificate(pubKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}
		var ok bool
		pubKey, ok = cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate public key is not RSA")
		}
	} else {
		// Parse as public key
		pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}
		var ok bool
		pubKey, ok = pubKeyInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
	}

	return &UserRSAKeys{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// Get user from basic auth
func (cs *ConfigServer) getUserFromAuth(r *http.Request) (*User, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}

	user, exists := cs.users[username]
	if !exists {
		return nil, false
	}

	// Use constant time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare([]byte(password), []byte(user.Password)) != 1 {
		return nil, false
	}

	return user, true
}

// Basic auth middleware
func (cs *ConfigServer) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := cs.getUserFromAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Store user in request context for later use
		r.Header.Set("X-Config-User", user.Username)
		next.ServeHTTP(w, r)
	}
}

// Encrypt data using user's key (symmetric or asymmetric based on user config)
func (cs *ConfigServer) encrypt(plaintext string, user *User) (string, error) {
	if user.EncryptionKey != "" {
		// Symmetric encryption
		return cs.encryptSymmetric(plaintext, user)
	} else {
		// Asymmetric encryption
		return cs.encryptAsymmetric(plaintext, user)
	}
}

// Decrypt data using user's key (symmetric or asymmetric based on user config)
func (cs *ConfigServer) decrypt(ciphertext string, user *User) (string, error) {
	if user.EncryptionKey != "" {
		// Symmetric decryption
		return cs.decryptSymmetric(ciphertext, user)
	} else {
		// Asymmetric decryption
		return cs.decryptAsymmetric(ciphertext, user)
	}
}

// Encrypt data using AES-256-GCM (symmetric)
func (cs *ConfigServer) encryptSymmetric(plaintext string, user *User) (string, error) {
	key, err := base64.StdEncoding.DecodeString(user.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encryption key for user %s: %v", user.Username, err)
	}
	return u.Encrypt(plaintext, string(key))
}

// Decrypt data using AES-256-GCM (symmetric)
func (cs *ConfigServer) decryptSymmetric(ciphertext string, user *User) (string, error) {
	key, err := base64.StdEncoding.DecodeString(user.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encryption key for user %s: %v", user.Username, err)
	}
	return u.Decrypt(ciphertext, string(key))
}

// Encrypt data using RSA-OAEP (asymmetric)
func (cs *ConfigServer) encryptAsymmetric(plaintext string, user *User) (string, error) {
	rsaKeys, exists := cs.userRSAKeys[user.Username]
	if !exists {
		return "", fmt.Errorf("RSA keys not loaded for user %s", user.Username)
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKeys.PublicKey, []byte(plaintext), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt data using RSA-OAEP (asymmetric)
func (cs *ConfigServer) decryptAsymmetric(ciphertext string, user *User) (string, error) {
	rsaKeys, exists := cs.userRSAKeys[user.Username]
	if !exists {
		return "", fmt.Errorf("RSA keys not loaded for user %s", user.Username)
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaKeys.PrivateKey, data, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Process file content and decrypt '{cipher}xxx' patterns using first user's key (for file serving)
func (cs *ConfigServer) processFileContent(content []byte) ([]byte, error) {
	if len(cs.config.Server.Users) == 0 {
		return content, nil
	}

	// Use first user's key for file content decryption
	// In a real implementation, you might want to use a service key or determine user differently
	firstUser := &cs.config.Server.Users[0]

	contentStr := string(content)

	// Find all '{cipher}xxx' patterns and decrypt them
	result := cs.cipherRegex.ReplaceAllStringFunc(contentStr, func(match string) string {
		// Extract the encrypted data (remove '{cipher}' prefix and quotes)
		encryptedData := strings.TrimPrefix(strings.TrimSuffix(match, "'"), "'{cipher}")

		// Decrypt the data
		decrypted, err := cs.decrypt(encryptedData, firstUser)
		if err != nil {
			log.Printf("Failed to decrypt cipher data: %v", err)
			return match // Return original if decryption fails
		}

		return decrypted
	})

	return []byte(result), nil
}

// Handle encrypt endpoint
func (cs *ConfigServer) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := cs.getUserFromAuth(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	var plaintext string
	contentType := r.Header.Get("Content-Type")

	// Check if it's JSON payload
	if strings.Contains(contentType, "application/json") {
		var req EncryptRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		plaintext = req.Data
	} else {
		// Treat as raw text
		plaintext = string(body)
	}

	encrypted, err := cs.encrypt(plaintext, user)
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}

	// Return response based on request content type
	if strings.Contains(contentType, "application/json") {
		response := EncryptResponse{Data: encrypted}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		// Return raw encrypted text (Spring Boot Config Server style)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(encrypted))
	}
}

// Handle decrypt endpoint
func (cs *ConfigServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := cs.getUserFromAuth(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	var ciphertext string
	contentType := r.Header.Get("Content-Type")

	// Check if it's JSON payload
	if strings.Contains(contentType, "application/json") {
		var req DecryptRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		ciphertext = req.Data
	} else {
		// Treat as raw text
		ciphertext = string(body)
	}

	decrypted, err := cs.decrypt(ciphertext, user)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}

	// Return response based on request content type
	if strings.Contains(contentType, "application/json") {
		response := DecryptResponse{Data: decrypted}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		// Return raw decrypted text (Spring Boot Config Server style)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(decrypted))
	}
}

// Handle file serving using backend
func (cs *ConfigServer) handleFileServing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestPath := strings.TrimPrefix(r.URL.Path, "/")
	if requestPath == "" {
		http.Error(w, "Path required", http.StatusBadRequest)
		return
	}

	// Try to get file content
	content, err := cs.backend.GetFile(requestPath, "", "", "")
	if err != nil {
		// Check if it's a directory request
		files, listErr := cs.backend.ListFiles(requestPath)
		if listErr != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		// Return directory listing
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path":  requestPath,
			"files": files,
		})
		return
	}

	// Process file content (decrypt {cipher} patterns)
	processedContent, err := cs.processFileContent(content)
	if err != nil {
		http.Error(w, "Unable to process file content", http.StatusInternalServerError)
		return
	}

	// Determine content type based on file extension
	contentType := "text/plain"
	ext := strings.ToLower(filepath.Ext(requestPath))
	switch ext {
	case ".json":
		contentType = "application/json"
	case ".yaml", ".yml":
		contentType = "application/yaml"
	case ".xml":
		contentType = "application/xml"
	case ".properties":
		contentType = "text/plain"
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(processedContent)
}

func main() {
	configFile := os.Getenv("CONFIG_FILE")
	if configFile == "" {
		configFile = "config.yaml"
	}

	// Load configuration
	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Create config server
	server, err := NewConfigServer(config)
	if err != nil {
		log.Fatal("Failed to create config server:", err)
	}

	// Setup routes
	http.HandleFunc("/encrypt", server.basicAuth(server.handleEncrypt))
	http.HandleFunc("/decrypt", server.basicAuth(server.handleDecrypt))
	http.HandleFunc("/", server.handleFileServing)

	log.Printf("Config Server starting on port %s", config.Server.Port)
	log.Printf("Backend: %s", config.Server.Backend)
	log.Printf("Users configured: %d", len(config.Server.Users))

	log.Fatal(http.ListenAndServe(":"+config.Server.Port, nil))
}
