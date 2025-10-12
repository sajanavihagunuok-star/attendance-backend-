const express = require('express');
const router = express.Router();

router.get('/:code', (req, res) => {
  res.json({ code: req.params.code, name: 'Sample Course' }); // Stub
});

module.exports = router;