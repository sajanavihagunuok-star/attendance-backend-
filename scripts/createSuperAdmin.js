const { Client } = require('pg');
const bcrypt = require('bcryptjs');

async function run() {
  const DB = process.env.DATABASE_URL;
  if (!DB) {
    console.error('ERROR: DATABASE_URL not set');
    process.exit(1);
  }

  const email = process.env.SUPER_EMAIL || 'owner@example.com';
  const pass = process.env.SUPER_PASS || 'ChangeMe123!';
  const name = process.env.SUPER_NAME || 'Owner';
  const role = process.env.SUPER_ROLE || 'superadmin';

  const client = new Client({ connectionString: DB, ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false });
  await client.connect();

  try {
    const check = await client.query('SELECT id FROM users WHERE lower(email)=lower($1) LIMIT 1', [email]);
    if (check.rows.length) {
      console.log('Super admin already exists:', email);
      await client.end();
      return;
    }

    const hash = bcrypt.hashSync(pass, 10);
    const now = new Date().toISOString();

    await client.query(
      `INSERT INTO users (email, name, role, password_hash, created_at)
       VALUES ($1,$2,$3,$4,$5)`,
      [email, name, role, hash, now]
    );

    console.log('Super admin created:', email);
    console.log('Password:', pass);
  } catch (err) {
    console.error('Failed creating super admin:', err.message || err);
  } finally {
    await client.end();
  }
}

run().catch(e => { console.error(e); process.exit(1); });