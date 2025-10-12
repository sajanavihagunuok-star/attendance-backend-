const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  // Replace with real DB lookup
  if (email === 'admin@example.com' && password === 'admin') {
    const token = jwt.sign({ email, role: 'admin', institute_id: 1 }, process.env.JWT_SECRET || 'secret');
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

module.exports = router;