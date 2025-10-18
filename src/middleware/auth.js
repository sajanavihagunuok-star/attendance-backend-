const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    if (!decoded || typeof decoded !== 'object' || !decoded.sub) {
      return res.status(401).json({ message: 'Invalid token payload' });
    }

    req.user = {
      id: decoded.sub,
      role: decoded.role || decoded.rol || null,
      email: decoded.email || null,
      raw: decoded
    };

    return next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).json({ message: 'Internal auth error' });
  }
}

module.exports = { requireAuth };
