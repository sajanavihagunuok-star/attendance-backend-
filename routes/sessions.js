const express = require('express');
const router = express.Router();

router.get('/', (req, res) => res.json({ ok: true, sessions: [] }));
router.get('/:id', (req, res) => res.json({ ok: true, id: req.params.id }));

module.exports = router;
