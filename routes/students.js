const express = require('express');
const router = express.Router();

// Minimal stub routes
router.get('/', (req, res) => res.json({ ok: true, list: [] }));
router.get('/:id', (req, res) => res.json({ ok: true, id: req.params.id }));

module.exports = router;
