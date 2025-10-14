// backend/db.js
// Safe DB helper: validates at startup and returns friendly errors when DNS/connection fails.

const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('[db][ERROR] idle client error', err && err.stack || err);
});

let validated = false;

async function validateConnection() {
  try {
    const client = await pool.connect();
    try {
      await client.query('SELECT 1');
      validated = true;
      console.log('[db] connection validated');
    } finally {
      client.release();
    }
  } catch (err) {
    validated = false;
    console.error('[db][FATAL] validation failed:', err && err.message || err);
    // Do not throw to allow server to start; controllers will get friendly error.
  }
}
validateConnection().catch(() => { /* logged above */ });

// Safe query wrapper: if initial validation failed, throw a controlled error
async function query(text, params) {
  if (!validated) {
    const e = new Error('Database unreachable or DNS resolution failed');
    e.code = 'DB_UNREACHABLE';
    throw e;
  }
  try {
    return await pool.query(text, params);
  } catch (err) {
    err.message = `[db][QUERY_ERR] ${err.message}`;
    throw err;
  }
}

module.exports = {
  query,
  connect: () => pool.connect(),
  pool
};