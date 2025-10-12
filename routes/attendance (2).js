const express = require('express');
const router = express.Router();

router.post('/mark', (req, res) => {
  res.json({ success: true }); // Stub
});

router.get('/report', (req, res) => {
  res.json([]); // Stub
});

module.exports = router;