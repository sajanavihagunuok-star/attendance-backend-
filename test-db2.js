require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 10000,
  ssl: (process.env.DEBUG_TLS === '1') ? { rejectUnauthorized: false } : { rejectUnauthorized: true }
});

(async () => {
  try {
    const { rows } = await pool.query('SELECT NOW() as now');
    console.log('DB OK', rows[0].now.toString());
  } catch (e) {
    console.error('DB CONNECT ERROR:', e && e.code, e && e.message);
    console.error(e && e.stack);
  } finally {
    await pool.end().catch(()=>{});
  }
})();