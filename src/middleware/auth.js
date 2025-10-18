const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  // no-op verifier that still parses token into req.auth if present
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
      req.auth = decoded;
    } catch (err) {
      // leave req.auth undefined for invalid token, let requireAuth handle actual protection
    }
    return next();
  } catch (err) {
    console.error('verifyToken error', err);
    return next();
  }
}

function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    if (!decoded || typeof decoded !== 'object' || !decoded.sub) {
      return res.status(401).json({ message: 'Invalid token payload' });
    }

    // Attach token claims where index.js expects them
    req.auth = decoded;
    // Also attach req.user for other code that might expect it
    req.user = req.user || {};
    req.user.id = req.user.id || decoded.sub;
    req.user.role = req.user.role || decoded.role || decoded.rol || null;
    req.user.email = req.user.email || decoded.email || null;

    return next();
  } catch (err) {
    console.error('requireAuth error:', err);
    return res.status(500).json({ message: 'Internal auth error' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    try {
      const r = (req.auth && (req.auth.role || req.auth.rol)) || (req.user && req.user.role);
      if (!r) return res.status(403).json({ message: 'Missing role' });
      if (Array.isArray(role) ? role.includes(r) : r === role) return next();
      return res.status(403).json({ message: 'Insufficient role' });
    } catch (err) {
      console.error('requireRole error:', err);
      return res.status(500).json({ message: 'Internal auth error' });
    }
  };
}

module.exports = { verifyToken, requireAuth, requireRole };
