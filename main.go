package main

import (
	"crypto/aes"
	"crypto/cipher"
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
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port     string `yaml:"port"`
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"server"`
	Directories []DirectoryConfig `yaml:"directories"`
	Encryption  struct {
		Type       string `yaml:"type"`                  // "symmetric" or "asymmetric"
		Key        string `yaml:"key"`                   // For symmetric: base64 key, for asymmetric: private key path
		PublicKey  string `yaml:"public_key,omitempty"`  // For asymmetric: public key path
		PrivateKey string `yaml:"private_key,omitempty"` // For asymmetric: private key path
	} `yaml:"encryption"`
}

type DirectoryConfig struct {
	Directory string `yaml:"directory"` // Absolute directory path
}

type ConfigServer struct {
	config        *Config
	cipherRegex   *regexp.Regexp
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
	aesKey        []byte
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
	if config.Server.Username == "" {
		config.Server.Username = "config"
	}
	if config.Server.Password == "" {
		config.Server.Password = "secret"
	}
	if config.Encryption.Type == "" {
		config.Encryption.Type = "symmetric"
	}

	return &config, nil
}

func NewConfigServer(config *Config) (*ConfigServer, error) {
	cs := &ConfigServer{
		config:      config,
		cipherRegex: regexp.MustCompile(`'\{cipher\}([A-Za-z0-9+/=]+)'`),
	}

	// Setup encryption based on type
	switch config.Encryption.Type {
	case "symmetric":
		if config.Encryption.Key == "" {
			// Default key
			config.Encryption.Key = "bXlzZWNyZXRrZXkxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=" // base64 of 32 chars
		}

		key, err := base64.StdEncoding.DecodeString(config.Encryption.Key)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 encryption key: %v", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("encryption key must be 32 bytes for AES-256")
		}
		cs.aesKey = key

	case "asymmetric":
		if config.Encryption.PrivateKey == "" {
			return nil, fmt.Errorf("private key path required for asymmetric encryption")
		}
		if config.Encryption.PublicKey == "" {
			return nil, fmt.Errorf("public key path required for asymmetric encryption")
		}

		// Load private key
		privKeyData, err := os.ReadFile(config.Encryption.PrivateKey)
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
		cs.rsaPrivateKey = privKey

		// Load public key
		pubKeyData, err := os.ReadFile(config.Encryption.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %v", err)
		}

		pubKeyBlock, _ := pem.Decode(pubKeyData)
		if pubKeyBlock == nil {
			return nil, fmt.Errorf("failed to decode public key PEM")
		}

		pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %v", err)
		}

		pubKey, ok := pubKeyInterface.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
		cs.rsaPublicKey = pubKey

	default:
		return nil, fmt.Errorf("unsupported encryption type: %s", config.Encryption.Type)
	}

	return cs, nil
}

// Basic auth middleware
func (cs *ConfigServer) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Use constant time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(username), []byte(cs.config.Server.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(password), []byte(cs.config.Server.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Config Server"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// Encrypt data based on configured encryption type
func (cs *ConfigServer) encrypt(plaintext string) (string, error) {
	switch cs.config.Encryption.Type {
	case "symmetric":
		return cs.encryptSymmetric(plaintext)
	case "asymmetric":
		return cs.encryptAsymmetric(plaintext)
	default:
		return "", fmt.Errorf("unsupported encryption type")
	}
}

// Decrypt data based on configured encryption type
func (cs *ConfigServer) decrypt(ciphertext string) (string, error) {
	switch cs.config.Encryption.Type {
	case "symmetric":
		return cs.decryptSymmetric(ciphertext)
	case "asymmetric":
		return cs.decryptAsymmetric(ciphertext)
	default:
		return "", fmt.Errorf("unsupported encryption type")
	}
}

// Encrypt data using AES-256-GCM
func (cs *ConfigServer) encryptSymmetric(plaintext string) (string, error) {
	block, err := aes.NewCipher(cs.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt data using AES-256-GCM
func (cs *ConfigServer) decryptSymmetric(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(cs.aesKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, cipherBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, cipherBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Encrypt data using RSA-OAEP
func (cs *ConfigServer) encryptAsymmetric(plaintext string) (string, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, cs.rsaPublicKey, []byte(plaintext), nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt data using RSA-OAEP
func (cs *ConfigServer) decryptAsymmetric(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, cs.rsaPrivateKey, data, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Process file content and decrypt {cipher} patterns
func (cs *ConfigServer) processFileContent(content []byte) ([]byte, error) {
	contentStr := string(content)

	// Find all {cipher}xxx patterns and decrypt them
	result := cs.cipherRegex.ReplaceAllStringFunc(contentStr, func(match string) string {
		// Extract the encrypted data (remove {cipher} prefix)
		encryptedData := strings.TrimPrefix(match, "'{cipher}")
		encryptedData = strings.TrimSuffix(encryptedData, "'")
		// Decrypt the data
		decrypted, err := cs.decrypt(encryptedData)
		if err != nil {
			log.Printf("Failed to decrypt cipher data: %v", err)
			return match // Return original if decryption fails
		}

		return decrypted
	})

	return []byte(result), nil
}

// Check if a directory is allowed to be served
func (cs *ConfigServer) isDirectoryAllowed(dirPath string) bool {
	for _, dirConfig := range cs.config.Directories {
		if dirPath == dirConfig.Directory {
			return true
		}
	}
	return false
}

// Handle encrypt endpoint
func (cs *ConfigServer) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

	encrypted, err := cs.encrypt(plaintext)
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

	decrypted, err := cs.decrypt(ciphertext)
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

// Handle file serving with allowed directories check
func (cs *ConfigServer) handleFileServing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the requested path (this is the full path)
	requestPath := strings.TrimPrefix(r.URL.Path, "/")
	if requestPath == "" {
		http.Error(w, "Path required", http.StatusBadRequest)
		return
	}

	// The request path is the full file path
	fullPath := "/" + requestPath

	// Get the directory of the requested file
	dirPath := filepath.Dir(fullPath)

	// Check if this directory is in the allowed list
	if !cs.isDirectoryAllowed(dirPath) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Check if file exists
	fileInfo, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// If it's a directory, list contents
	if fileInfo.IsDir() {
		files, err := os.ReadDir(fullPath)
		if err != nil {
			http.Error(w, "Unable to read directory", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		var fileList []string
		for _, file := range files {
			fileList = append(fileList, file.Name())
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"path":  requestPath,
			"files": fileList,
		})
		return
	}

	// Read file content
	content, err := os.ReadFile(fullPath)
	if err != nil {
		http.Error(w, "Unable to read file", http.StatusInternalServerError)
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
	ext := strings.ToLower(filepath.Ext(fullPath))
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

	// Setup routes with basic auth protection
	http.HandleFunc("/encrypt", server.basicAuth(server.handleEncrypt))
	http.HandleFunc("/decrypt", server.basicAuth(server.handleDecrypt))
	http.HandleFunc("/", server.handleFileServing) // File serving without auth (like Spring Boot)

	log.Printf("Config Server starting on port %s", config.Server.Port)
	log.Printf("Encryption type: %s", config.Encryption.Type)
	log.Printf("Basic auth: %s:***", config.Server.Username)
	log.Printf("Configured directories: %d", len(config.Directories))
	for _, dir := range config.Directories {
		log.Printf("  %s", dir.Directory)
	}

	log.Fatal(http.ListenAndServe(":"+config.Server.Port, nil))
}
