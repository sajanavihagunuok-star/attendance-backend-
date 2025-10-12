// backend/middleware/auth.js
// Minimal authentication/authorization middleware for local development.
// Replace with real JWT/session logic in production.

module.exports.verifyToken = function verifyToken(req, res, next) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) {
    // Minimal local testing behavior: attach a fake admin user
    // If you need different roles for testing, change role value here.
    req.user = { id: 'test-user', role: 'admin', institute_id: 'test-institute' };
  } else {
    req.user = null;
  }
  return next();
};

module.exports.requireRole = function requireRole(role) {
  return function (req, res, next) {
    const user = req.user || {};
    if (!user.role) return res.status(403).json({ error: 'Role required' });
    if (Array.isArray(role)) {
      if (!role.includes(user.role)) return res.status(403).json({ error: 'Insufficient role' });
    } else {
      if (user.role !== role) return res.status(403).json({ error: 'Insufficient role' });
    }
    next();
  };
};