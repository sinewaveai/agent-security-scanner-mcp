// Benchmark corpus: Go security vulnerabilities
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// --- SQL Injection ---

func unsafeQuery(db *sql.DB, userID string) {
	// VULN: sql-injection-db
	db.Query("SELECT * FROM users WHERE id = " + userID)
}

func unsafeExec(db *sql.DB, name string) {
	// VULN: sql-injection-db
	db.Exec(fmt.Sprintf("INSERT INTO users (name) VALUES ('%s')", name))
}

func safeQuery(db *sql.DB, userID string) {
	// SAFE: sql-injection-db
	db.Query("SELECT * FROM users WHERE id = $1", userID)
}

func safeExec(db *sql.DB, name string) {
	// SAFE: sql-injection-db
	db.Exec("INSERT INTO users (name) VALUES ($1)", name)
}

// --- Command Injection ---

func unsafeExecCommand(userInput string) {
	// VULN: command-injection-exec
	exec.Command("sh", "-c", "echo "+userInput)
}

func safeExecCommand(filename string) {
	// SAFE: command-injection-exec
	exec.Command("cat", filename)
}

// --- Path Traversal ---

func unsafeReadFile(userPath string) {
	// VULN: path-traversal
	os.Open("/data/" + userPath)
}

func unsafeReadFile2(userPath string) {
	// VULN: path-traversal
	ioutil.ReadFile("/uploads/" + userPath)
}

func safeReadFile(filename string) {
	// SAFE: path-traversal
	cleanPath := filepath.Clean(filename)
	if filepath.IsAbs(cleanPath) {
		return
	}
	os.Open(filepath.Join("/data", cleanPath))
}

// --- SSRF ---

func unsafeHTTPGet(url string) {
	// VULN: ssrf-http
	http.Get("http://internal/" + url)
}

func safeHTTPGet() {
	// SAFE: ssrf-http
	http.Get("https://api.example.com/data")
}

// --- Weak Cryptography ---

func weakHashMD5(data []byte) {
	// VULN: weak-hash-md5
	md5.Sum(data)
}

func weakHashSHA1(data []byte) {
	// VULN: weak-hash-sha1
	sha1.Sum(data)
}

func strongHash(data []byte) {
	// SAFE: weak-hash-md5
	sha256.Sum256(data)
}

// --- Hardcoded Credentials ---

// VULN: hardcoded-api-key
var apiKey = "AKIAIOSFODNN7EXAMPLE"

// VULN: hardcoded-password
var password = "SuperSecret123!"

// SAFE: hardcoded-api-key
var apiKeyEnv = os.Getenv("API_KEY")

// --- XSS Response Writer ---

func unsafeResponseWrite(w http.ResponseWriter, userInput string) {
	// VULN: xss-response-writer
	w.Write([]byte(userInput))
}

func main() {}
