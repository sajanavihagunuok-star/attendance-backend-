const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

pool.on('error', (err) => {
  console.error('[db][ERROR] idle client error', err?.stack || err);
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
    console.error('[db][FATAL] validation failed:', err?.message || err);
  }
}
validateConnection().catch(() => {});

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