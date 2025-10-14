const { Client } = require('pg');
(async () => {
  try {
    const client = new Client({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
    await client.connect();
    const r = await client.query('SELECT now()');
    console.log('CONNECTED OK', r.rows[0]);
    await client.end();
  } catch (e) {
    console.error('CONNECT-ERROR', e);
    process.exit(1);
  }
})();