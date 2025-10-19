const { Client } = require("pg");
const bcrypt = require("bcrypt");

(async () => {
  try {
    const email = process.env.OWNER_EMAIL;
    const password = process.env.OWNER_PASSWORD;
    const db = process.env.DATABASE_URL;
    if (!email || !password || !db) {
      console.error("Missing env OWNER_EMAIL, OWNER_PASSWORD, or DATABASE_URL");
      process.exit(1);
    }
    const client = new Client({ connectionString: db });
    await client.connect();

    // ensure required columns exist is already verified by you
    const hash = await bcrypt.hash(password, 12);

    // Upsert by email; preserve other columns if present
    const sql = `
      INSERT INTO public.users (email, name, role, password_hash, created_at)
      VALUES ($1, $2, $3, $4, now())
      ON CONFLICT (email) DO UPDATE
      SET name = EXCLUDED.name,
          role = EXCLUDED.role,
          password_hash = EXCLUDED.password_hash,
          created_at = public.users.created_at
      RETURNING id, email, role;
    `;
    const res = await client.query(sql, [email, email, 'owner', hash]);
    console.log('Upsert result:', res.rows[0]);
    await client.end();
  } catch (err) {
    console.error('ERROR:', err.message || err);
    process.exit(1);
  }
})();
