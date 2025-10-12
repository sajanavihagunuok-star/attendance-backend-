const express = require('express');
const router = express.Router();
const { Client } = require('pg');

router.post('/', async (req, res) => {
  const { name, start_date, end_date } = req.body;
  const institute_id = req.user.institute_id;
  if (!name || !start_date || !end_date) return res.status(400).json({ error: 'Missing fields' });

  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    await client.query(
      'INSERT INTO academic_years (institute_id, name, start_date, end_date) VALUES ($1, $2, $3, $4)',
      [institute_id, name, start_date, end_date]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    await client.end();
  }
});

router.get('/', async (req, res) => {
  const institute_id = req.user.institute_id;
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    const result = await client.query(
      'SELECT * FROM academic_years WHERE institute_id = $1 ORDER BY start_date DESC',
      [institute_id]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    await client.end();
  }
});

router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  const institute_id = req.user.institute_id;
  const client = new Client({ connectionString: process.env.DATABASE_URL });
  await client.connect();
  try {
    await client.query(
      'DELETE FROM academic_years WHERE id = $1 AND institute_id = $2',
      [id, institute_id]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    await client.end();
  }
});

module.exports = router;