// JavaScript vulnerabilities for SARIF testing

const API_KEY = "sk_live_abc123xyz789";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// SQL injection
function getUser(userId) {
    db.query("SELECT * FROM users WHERE id = " + userId);
}

// XSS vulnerability
function displayName(name) {
    document.innerHTML = name;
}

// Command injection
const { exec } = require('child_process');
function runCommand(cmd) {
    exec(cmd);
}

// Eval usage
function processCode(code) {
    eval(code);
}
