const express = require('express');
const router = express.Router();

router.post('/', (req, res) => {
  const { name, course_id, date, time } = req.body;
  if (!name || !course_id || !date || !time) return res.status(400).json({ error: 'Missing fields' });
  res.json({ success: true }); // Stub
});

module.exports = router;