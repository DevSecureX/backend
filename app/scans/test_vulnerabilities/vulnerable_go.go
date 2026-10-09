package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"
	
	_ "github.com/lib/pq"
)

// Global variables with hardcoded secrets - Gosec should detect these
var (
	APIKey      = "sk-1234567890abcdefghijklmnopqrstuvwxyz"     // G101: hardcoded credentials
	DBPassword  = "admin123"                                   // G101: hardcoded credentials  
	JWTSecret   = "my-super-secret-jwt-key-12345"             // G101: hardcoded credentials
	DatabaseURL = "postgres://admin:password123@localhost/db" // G101: hardcoded credentials
)

// Command injection vulnerability - G204
func ExecuteUserCommand(userInput string) error {
	// Direct execution of user input - command injection
	cmd := exec.Command("sh", "-c", userInput) // G204: Subprocess launched with potential tainted input
	return cmd.Run()
}

// SQL injection vulnerability - G201
func GetUserByName(db *sql.DB, username string) (*sql.Rows, error) {
	// SQL injection via string formatting
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username) // G201: SQL string formatting
	return db.Query(query)
}

// Weak cryptographic hash - G401
func HashPassword(password string) string {
	// Using MD5 for password hashing
	h := md5.New() // G401: Use of weak cryptographic primitive
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Path traversal vulnerability - G304
func ReadUserFile(filename string) ([]byte, error) {
	// Reading files without validation
	fullPath := filepath.Join("/uploads", filename)
	return ioutil.ReadFile(fullPath) // G304: Potential file inclusion via variable
}

// Insecure file permissions - G302
func CreateTempFile(data []byte) error {
	// Creating file with overly permissive permissions
	return ioutil.WriteFile("/tmp/sensitive.txt", data, 0777) // G302: Poor file permissions
}

// Weak random number generation - G404
func GenerateSessionID() string {
	// This would be flagged if using math/rand without proper seeding
	// For demonstration, we'll show the pattern
	return "session_" + APIKey[0:10] // Using part of secret as session ID
}

// Insecure HTTP client - G107
func MakeAPICall(url string) (*http.Response, error) {
	// Creating HTTP client with disabled security
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // G402: TLS InsecureSkipVerify
	}
	client := &http.Client{Transport: tr}
	return client.Get(url)
}

// Unsafe pointer operations - G103
func UnsafeMemoryAccess(data []byte) {
	// Converting slice to unsafe pointer
	ptr := unsafe.Pointer(&data[0]) // G103: Use of unsafe calls
	_ = ptr
}

// Directory traversal in HTTP handler - G304
func FileServerHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// Serving files without path validation
	http.ServeFile(w, r, filename) // G304: Potential file inclusion via variable
}

// Weak cryptography - DES usage - G405
func EncryptWithDES(data, key []byte) []byte {
	// This would be flagged if using DES encryption
	// Simulating weak encryption pattern
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)] // Simple XOR (weak)
	}
	return result
}

// Binding to all interfaces - G102
func StartServer() {
	// Binding HTTP server to all interfaces
	http.ListenAndServe("0.0.0.0:8080", nil) // G102: Bind to all interfaces
}

// Error handling that could leak information - G104
func ProcessFile(filename string) {
	data, err := ioutil.ReadFile(filename)
	_ = err // G104: Errors unhandled - could mask security issues
	
	fmt.Println(string(data))
}

// Subprocess with potential for injection - G204
func BackupDirectory(directory string) {
	// Using user input in command construction
	cmd := exec.Command("tar", "-czf", "backup.tar.gz", directory+"/*") // G204: Potential command injection
	cmd.Run()
}

// Template injection potential - G203
func RenderTemplate(userInput string) string {
	// Direct template rendering with user input
	template := "Hello, " + userInput + "!" // G203: Use of unescaped data in template
	return template
}

// Race condition potential - G601
func ProcessUsers(users []User) {
	for _, user := range users {
		go func() {
			// Capturing loop variable in goroutine
			ProcessUser(user) // G601: Implicit memory aliasing in for loop
		}()
	}
}

type User struct {
	ID   int
	Name string
}

func ProcessUser(user User) {
	fmt.Printf("Processing user: %s\n", user.Name)
}

// Hardcoded credentials in different contexts - G101
const (
	AdminPassword = "admin123"                    // G101: hardcoded password
	SecretToken   = "token_abc123xyz"            // G101: hardcoded token
	EncryptionKey = "1234567890abcdef1234567890" // G101: hardcoded key
)

// Network binding issues - G102
func CreateListener() {
	// Binding to all interfaces without proper access controls
	listener, _ := net.Listen("tcp", ":0") // G102: Bind to all interfaces
	defer listener.Close()
}

// TLS configuration issues - G402
func ConfigureHTTPSClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,    // G402: TLS InsecureSkipVerify set true
			MinVersion:         tls.VersionTLS10, // G402: TLS MinVersion too low
		},
	}
	return &http.Client{Transport: tr}
}

// File creation with weak permissions - G302
func CreateSecretFile(secret string) {
	// Creating file with world-readable permissions
	ioutil.WriteFile("/tmp/secret.txt", []byte(secret), 0644) // G302: Poor file permissions for sensitive data
}

// Integer overflow potential - G115
func CalculateSize(userInput string) int {
	size := len(userInput)
	// Potential integer overflow in calculations
	return size * size * size // Could overflow with large input
}

// Main function demonstrating vulnerable patterns
func main() {
	fmt.Println("Vulnerable Go application for security testing")
	
	// Use hardcoded credentials
	fmt.Printf("API Key: %s\n", APIKey)
	fmt.Printf("DB Password: %s\n", DBPassword)
	
	// Demonstrate weak cryptography
	hashedPassword := HashPassword("userpassword123")
	fmt.Printf("Weak hash: %s\n", hashedPassword)
	
	// File operations with potential issues
	CreateSecretFile(JWTSecret)
	
	// Command that could be dangerous
	ExecuteUserCommand("echo 'test command'")
	
	// Start server (commented out to prevent actual binding)
	// StartServer()
	
	fmt.Println("Application started with multiple security vulnerabilities")
}