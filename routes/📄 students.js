const express = require('express');
const router = express.Router();
const { Client } = require('pg');

router.post('/', async (req, res) => {
  const { name, email } = req.body;
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    await client.query('INSERT INTO students (name, email) VALUES ($1, $2)', [name, email]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    await client.end();
  }
});

module.exports = router;