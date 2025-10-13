// backend/middleware/auth.js
// Minimal authentication/authorization middleware for local development.
// Keeps behavior safe for production only as a placeholder — replace with real JWT/session logic later.

const jwt = require('jsonwebtoken');

function getTokenFromHeader(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  return auth.slice(7).trim();
}

function verifyToken(req, res, next) {
  const token = getTokenFromHeader(req);
  if (!token) {
    req.user = null;
    return next();
  }

  const secret = process.env.JWT_SECRET || '';
  if (!secret) {
    // No secret configured: attach a basic test user for local/dev convenience
    req.user = { id: 'test-user', role: 'admin', institute_id: 'test-institute' };
    return next();
  }

  try {
    const payload = jwt.verify(token, secret);
    req.user = payload;
    return next();
  } catch (err) {
    // Invalid token: treat as unauthenticated
    req.user = null;
    return next();
  }
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  return next();
}

function requireRole(roleOrRoles) {
  return function (req, res, next) {
    const user = req.user || {};
    if (!user.role) return res.status(403).json({ error: 'Role required' });

    if (Array.isArray(roleOrRoles)) {
      if (!roleOrRoles.includes(user.role)) return res.status(403).json({ error: 'Insufficient role' });
      return next();
    }

    if (user.role !== roleOrRoles) return res.status(403).json({ error: 'Insufficient role' });
    return next();
  };
}

module.exports = {
  verifyToken,
  requireAuth,
  requireRole
};