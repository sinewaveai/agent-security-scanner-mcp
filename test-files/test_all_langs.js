// JavaScript test file for security scanning
const express = require('express');
const mysql = require('mysql');

// SQL Injection
app.get('/user', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.params.id;
  db.query(query);
});

// XSS
function displayUser(name) {
  document.getElementById('user').innerHTML = name;
}

// Command Injection
const { exec } = require('child_process');
function runCmd(cmd) {
  exec(cmd);
}

// Hardcoded Secret
const API_KEY = "sk-live-abc123xyz789secret";
