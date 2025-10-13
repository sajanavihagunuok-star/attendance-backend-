const express = require('express');
const router = express.Router();

// Try to get a pg Pool instance. Adjust the require path if your project exports the pool elsewhere.
let pool;
try {
  pool = require('../db');
  if (pool && pool.query && typeof pool.query !== 'function') pool = pool.pool || pool.default || pool;
} catch (e) {
  try { pool = global.pool; } catch (e2) { pool = null; }
}

function isUuid(v) { return typeof v === 'string' && /^[0-9a-fA-F-]{36}$/.test(v); }

router.get('/', async (req, res) => {
  try {
    const { course_id, lecturer_id, date_from, date_to } = req.query;
    const q = `SELECT id, title, course_id, lecturer_id, start_time, end_time, capacity, created_at
               FROM sessions WHERE true`;
    const params = [];
    let i = 1;
    if (course_id) { q += ` AND course_id = $${i++}`; params.push(course_id); }
    if (lecturer_id) { q += ` AND lecturer_id = $${i++}`; params.push(lecturer_id); }
    if (date_from) { q += ` AND start_time >= $${i++}`; params.push(date_from); }
    if (date_to) { q += ` AND end_time <= $${i++}`; params.push(date_to); }
    q += ' ORDER BY start_time DESC LIMIT 500';
    if (!pool || !pool.query) return res.status(500).json({ error: 'database pool not available' });
    const { rows } = await pool.query(q, params);
    res.json({ ok: true, sessions: rows });
  } catch (err) {
    console.error('sessions GET error', err && err.stack ? err.stack : err);
    res.status(500).json({ error: err.message || 'internal error' });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const id = req.params.id;
    if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
    if (!pool || !pool.query) return res.status(500).json({ error: 'database pool not available' });
    const q = 'SELECT id, title, course_id, lecturer_id, start_time, end_time, capacity, created_at FROM sessions WHERE id = $1 LIMIT 1';
    const { rows } = await pool.query(q, [id]);
    if (!rows || rows.length === 0) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true, session: rows[0] });
  } catch (err) {
    console.error('sessions/:id error', err && err.stack ? err.stack : err);
    res.status(500).json({ error: err.message || 'internal error' });
  }
});

module.exports = router;
