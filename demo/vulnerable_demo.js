// Demo: Vulnerable Code for Agent Security Scanner

// 1. XSS - innerHTML vulnerability
function displayMessage(userInput) {
  document.getElementById('output').innerHTML = userInput;
}

// 2. SQL Injection - template literal
function getUser(userId) {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

// 3. SQL Injection - simple concatenation
function deleteUser(id) {
  return db.query("DELETE FROM users WHERE id = " + id);
}

module.exports = { displayMessage, getUser, deleteUser };
