const express = require('express');
const router = express.Router();

// List users
router.get('/', (req, res) => res.json({ ok: true, users: [] }));

// Get single user
router.get('/:id', (req, res) => res.json({ ok: true, id: req.params.id }));

// Create user (stub)
router.post('/', (req, res) => res.status(201).json({ ok: true, created: req.body }));

// Update user (stub)
router.patch('/:id', (req, res) => res.json({ ok: true, id: req.params.id, updated: req.body }));

// Delete user (stub)
router.delete('/:id', (req, res) => res.json({ ok: true, id: req.params.id, deleted: true }));

module.exports = router;
