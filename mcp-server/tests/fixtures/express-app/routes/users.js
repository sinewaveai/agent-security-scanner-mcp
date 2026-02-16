const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireAuth } = require('../middleware/auth');

router.get('/:id', requireAuth, (req, res) => {
  const userId = req.params.id;
  const user = db.getUserById(userId);
  res.json(user);
});

router.get('/', requireAuth, (req, res) => {
  const search = req.query.q;
  const users = db.searchUsers(search);
  res.json(users);
});

module.exports = router;
