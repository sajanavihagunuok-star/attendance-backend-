const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.json(req.user);
});

router.patch('/password', (req, res) => {
  res.json({ success: true }); // Stub
});

module.exports = router;