// quick-check.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

(async () => {
  try {
    console.log('Using DATABASE_URL:', (process.env.DATABASE_URL || '').slice(0, 80) + '...');
    const r = await pool.query('SELECT version() AS v');
    console.log('DB connection OK:', r.rows[0].v);
  } catch (err) {
    console.error('DB connection error:', err.message);
    console.error(err);
  } finally {
    await pool.end();
  }
})();