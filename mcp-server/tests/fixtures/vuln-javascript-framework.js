// Test fixture: Express app with helmet + XSS + SQLi vulnerabilities
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();
app.use(helmet());
app.use(cors());

// XSS vulnerability (should be downgraded from error to warning due to helmet)
app.get('/page', (req, res) => {
  res.send(`<div>${req.query.name}</div>`);
  document.innerHTML = req.query.input;
});

// SQL injection (NOT mitigated by helmet - should stay as error)
app.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.params.id);
});
