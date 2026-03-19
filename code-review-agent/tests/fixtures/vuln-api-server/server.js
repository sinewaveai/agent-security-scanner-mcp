const express = require('express');
const sqlite3 = require('sqlite3');
const fs = require('fs');
const app = express();

app.use(express.json());

const db = new sqlite3.Database('./users.db');

// User registration
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  // SQL injection - string concatenation instead of parameterized query
  const query = `INSERT INTO users (username, email, password) VALUES ('${username}', '${email}', '${password}')`;
  db.run(query, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// User search - eval injection
app.get('/api/search', (req, res) => {
  const { filter } = req.query;
  // eval on user input - command injection
  const filterFn = eval(`(user) => ${filter}`);
  db.all('SELECT * FROM users', (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    const filtered = users.filter(filterFn);
    res.json(filtered);
  });
});

// Profile picture upload - path traversal
app.post('/api/upload', (req, res) => {
  const { filename, data } = req.body;
  // Arbitrary file write - no path sanitization
  fs.writeFile(`./uploads/${filename}`, Buffer.from(data, 'base64'), (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ path: `/uploads/${filename}` });
  });
});

// Debug endpoint - exposes server info
app.get('/api/debug', (req, res) => {
  res.json({
    env: process.env,
    cwd: process.cwd(),
    memory: process.memoryUsage(),
  });
});

app.listen(3000);
