const { Client } = require("pg");
const bcrypt = require("bcrypt");

(async () => {
  try {
    const email = process.env.OWNER_EMAIL;
    const password = process.env.OWNER_PASSWORD;
    const db = process.env.DATABASE_URL;
    if (!email || !password || !db) {
      console.error("Missing OWNER_EMAIL, OWNER_PASSWORD, or DATABASE_URL");
      process.exit(1);
    }

    const client = new Client({ connectionString: db });
    await client.connect();

    // Build normalized_email consistently with your DB trigger
    const normalized = email.trim().toLowerCase();

    // Hash password
    const hash = await bcrypt.hash(password, 12);

    // Upsert using normalized_email. If normalized_email column exists we use it,
    // otherwise fall back to email column. This covers both migration states.
    const hasNormalizedRes = await client.query(
      "SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='normalized_email'"
    );
    const useNormalized = hasNormalizedRes.rows.length > 0;

    let sql, params;
    if (useNormalized) {
      sql = `
        INSERT INTO public.users (email, normalized_email, name, role, password_hash, created_at)
        VALUES ($1, $2, $3, $4, $5, now())
        ON CONFLICT (normalized_email) DO UPDATE
        SET email = EXCLUDED.email,
            name = EXCLUDED.name,
            role = EXCLUDED.role,
            password_hash = EXCLUDED.password_hash
        RETURNING id, email, role;
      `;
      params = [email, normalized, email, 'owner', hash];
    } else {
      sql = `
        INSERT INTO public.users (email, name, role, password_hash, created_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (email) DO UPDATE
        SET name = EXCLUDED.name,
            role = EXCLUDED.role,
            password_hash = EXCLUDED.password_hash
        RETURNING id, email, role;
      `;
      params = [email, email, 'owner', hash];
    }

    const res = await client.query(sql, params);
    console.log("Upsert result:", res.rows[0]);
    await client.end();
    process.exit(0);
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
