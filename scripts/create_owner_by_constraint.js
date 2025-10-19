const { Client } = require("pg");
const bcrypt = require("bcrypt");
(async () => {
  try {
    const email = process.env.OWNER_EMAIL;
    const password = process.env.OWNER_PASSWORD;
    const db = process.env.DATABASE_URL;
    if (!email || !password || !db) { console.error("Missing OWNER_EMAIL, OWNER_PASSWORD, or DATABASE_URL"); process.exit(1); }
    const client = new Client({ connectionString: db });
    await client.connect();
    const normalized = email.trim().toLowerCase();
    const hash = await bcrypt.hash(password, 12);
    const sql = `
      INSERT INTO public.users (email, name, role, password_hash)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT ON CONSTRAINT users_normalized_email_key
      DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name, role = EXCLUDED.role, password_hash = EXCLUDED.password_hash
      RETURNING id, email, role;
    `;
    const res = await client.query(sql, [email, email, 'owner', hash]);
    console.log("Upsert result:", res.rows[0]);
    await client.end();
    process.exit(0);
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
