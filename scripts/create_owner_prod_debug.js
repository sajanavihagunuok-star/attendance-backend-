const { Client } = require('pg');
const bcrypt = require('bcrypt');

async function main() {
  const username = process.env.OWNER_USERNAME;
  const password = process.env.OWNER_PASSWORD;
  const databaseUrl = process.env.DATABASE_URL;
  if (!username || !password || !databaseUrl) {
    console.error('Missing env vars. Set OWNER_USERNAME, OWNER_PASSWORD, and DATABASE_URL');
    process.exit(1);
  }

  const client = new Client({ connectionString: databaseUrl });
  await client.connect();

  const createUsersSql =
    'CREATE TABLE IF NOT EXISTS users (' +
    'id SERIAL PRIMARY KEY,' +
    'username TEXT UNIQUE NOT NULL,' +
    'password_hash TEXT NOT NULL,' +
    \"role TEXT NOT NULL DEFAULT 'student',\" +
    'created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),' +
    'last_login TIMESTAMP WITH TIME ZONE' +
    ');';

  const hash = await bcrypt.hash(password, 12);

  const upsertSql =
    'INSERT INTO users (username, password_hash, role) ' +
    'VALUES (, , ) ' +
    'ON CONFLICT (username) DO UPDATE ' +
    'SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role, last_login = now() ' +
    'RETURNING id, username, role;';

  console.log('--- createUsersSql ---');
  console.log(createUsersSql);
  console.log('--- upsertSql ---');
  console.log(upsertSql);

  try {
    const resCreate = await client.query(createUsersSql);
    const res = await client.query(upsertSql, [username, hash, 'owner']);
    console.log('Owner upsert completed:', res.rows[0]);
  } catch (err) {
    console.error('PG ERROR:', err);
  } finally {
    await client.end();
  }
}

main().catch(err => { console.error('SCRIPT ERROR:', err); process.exit(1); });
