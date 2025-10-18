const jwt = require('jsonwebtoken');

function log(...args) {
  try { console.error.apply(console, args); } catch(e) {}
}

function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
      req.auth = decoded;
      req.user = req.user || {};
      req.user.id = req.user.id || decoded.sub;
      req.user.role = req.user.role || decoded.role || decoded.rol || null;
      req.user.email = req.user.email || decoded.email || null;
      log('verifyToken: token verified, sub=' + (decoded.sub || 'undefined'));
    } catch (err) {
      log('verifyToken: jwt.verify failed', err && err.message);
    }
    return next();
  } catch (err) {
    log('verifyToken error', err && err.stack || err);
    return next();
  }
}

function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Missing Authorization header' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    if (!decoded || typeof decoded !== 'object' || !decoded.sub) {
      return res.status(401).json({ message: 'Invalid token payload: missing sub' });
    }

    req.auth = decoded;
    req.user = req.user || {};
    req.user.id = req.user.id || decoded.sub;
    req.user.role = req.user.role || decoded.role || decoded.rol || null;
    req.user.email = req.user.email || decoded.email || null;

    return next();
  } catch (err) {
    console.error('requireAuth error:', err && err.stack || err);
    return res.status(500).json({ message: 'Internal auth error' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    try {
      const roleVal = (req.auth && (req.auth.role || req.auth.rol)) || (req.user && req.user.role);
      if (!roleVal) return res.status(403).json({ message: 'Missing role' });
      if (Array.isArray(role) ? role.includes(roleVal) : roleVal === role) return next();
      return res.status(403).json({ message: 'Insufficient role' });
    } catch (err) {
      console.error('requireRole error:', err && err.stack || err);
      return res.status(500).json({ message: 'Internal auth error' });
    }
  };
}

module.exports = { verifyToken, requireAuth, requireRole };

