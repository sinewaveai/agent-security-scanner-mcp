function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // IDOR: checks if user is authenticated but not if they own the requested resource
  // Any authenticated user can access any user's data via /users/:id
  req.user = { id: 'authenticated-user' };
  next();
}

module.exports = { requireAuth };
