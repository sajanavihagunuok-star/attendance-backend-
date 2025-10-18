/*
 db-test.js
 - uses pg Pool
 - attaches error handler to avoid unhandled 'error' events
 - runs two simple queries and exits
*/
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // optional: set a short statement_timeout or idleTimeoutMillis if you want
  // statement_timeout: 10000,
  // idleTimeoutMillis: 30000,
});

// handle unexpected errors on the pool (prevents process crash)
pool.on('error', (err, client) => {
  console.error('[pool][ERROR] Unexpected error on idle client', err && err.message ? err.message : err);
});

async function run() {
  let client;
  try {
    client = await pool.connect();
    console.log('connected');

    const res = await client.query("SELECT current_database() AS db, current_user AS user, version() AS ver;");
    console.table(res.rows);

    const now = await client.query("SELECT now() as now;");
    console.log('now:', now.rows[0].now);

  } catch (err) {
    console.error('[db][ERROR]', err && err.message ? err.message : err);
    // Not exiting immediately; allow pool to shut down cleanly below
  } finally {
    if (client) client.release();
    // give pending events a moment, then drain pool and exit
    try {
      await pool.end();
      console.log('pool closed');
    } catch (e) {
      console.error('[pool][END][ERROR]', e && e.message ? e.message : e);
    }
  }
}

run();
