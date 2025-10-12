// test-db.js
const { Pool } = require('pg');
const url = process.env.DATABASE_URL;
if (!url) {
  console.error('No DATABASE_URL in env'); process.exit(1);
}
const pool = new Pool({ connectionString: url });
(async () => {
  try {
    const r = await pool.query('SELECT 1 as ok');
    console.log('DB OK', r.rows);
    await pool.end();
  } catch (e) {
    console.error('DB ERR', e.message);
    process.exit(1);
  }
})();