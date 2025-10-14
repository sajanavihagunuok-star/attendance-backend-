// test-db.js
require('dotenv').config();
const { Pool } = require('pg');
(async () => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    const { rows } = await pool.query('SELECT NOW() as now');
    console.log('DB OK', rows[0].now.toString());
  } catch (e) {
    console.error('DB ERR', e.message || e);
  } finally {
    await pool.end();
  }
})();