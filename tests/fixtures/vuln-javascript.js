const crypto = require('crypto');
const child_process = require('child_process');
const mysql = require('mysql');

// 1. SQL Injection
function getUser(userId) {
  db.query("SELECT * FROM users WHERE id = " + userId);
}

// 2. XSS via innerHTML
function displayMessage(msg) {
  document.getElementById('output').innerHTML = msg;
}

// 3. Command Injection
function runCommand(userInput) {
  child_process.exec("ls " + userInput);
}

// 4. Hardcoded API key
const API_KEY = "sk_live_abc123def456ghi789";

// 5. Weak crypto (MD5)
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// 6. eval() usage
function calculate(expression) {
  return eval(expression);
}

// 7. document.write XSS
function writeOutput(data) {
  document.write(data);
}

// 8. Hardcoded secret
const DATABASE_PASSWORD = "super_secret_password_123";

// 9. outerHTML XSS
function setContent(el, content) {
  el.outerHTML = content;
}

// 10. Path traversal
function readFile(filename) {
  return require('fs').readFileSync('../' + filename);
}

// 11. Weak crypto (SHA1)
function hashToken(token) {
  return crypto.createHash('sha1').update(token).digest('hex');
}

// 12. NoSQL injection
function findUser(username) {
  return db.collection('users').find({ username: username });
}
