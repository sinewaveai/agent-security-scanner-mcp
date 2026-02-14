// Go vulnerabilities for SARIF testing
package main

import (
	"database/sql"
	"fmt"
	"os/exec"
)

const apiKey = "ghp_abc123xyz789secrettoken"

// SQL injection
func getUser(db *sql.DB, userID string) {
	query := "SELECT * FROM users WHERE id = " + userID
	db.Query(query)
}

// Command injection
func runCommand(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

// Hardcoded password
func connect() {
	password := "supersecretpassword123"
	fmt.Println(password)
}
