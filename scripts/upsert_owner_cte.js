const { Client } = require("pg");
const bcrypt = require("bcrypt");
(async () => {
  try {
    const db = process.env.DATABASE_URL;
    const email = process.env.OWNER_EMAIL;
    const password = process.env.OWNER_PASSWORD;
    if (!db || !email || !password) { console.error("Missing env DATABASE_URL, OWNER_EMAIL, or OWNER_PASSWORD"); process.exit(1); }

    const client = new Client({ connectionString: db });
    await client.connect();

    const normalized = email.trim().toLowerCase();
    const hash = await bcrypt.hash(password, 12);

    const sql = `
WITH updated AS (
  UPDATE public.users
  SET email = $1,
      name = $2,
      role = $3,
      password_hash = $4,
      -- keep created_at unchanged
      -- don't touch id
      updated_at = now()
  WHERE lower(email) = $5
  RETURNING id, email, role
)
INSERT INTO public.users (email, name, role, password_hash, created_at)
SELECT $1, $2, $3, $4, now()
WHERE NOT EXISTS (SELECT 1 FROM updated)
RETURNING id, email, role;
`;
    const params = [email, email, 'owner', hash, normalized];
    const res = await client.query(sql, params);
    // If update happened, it returns from updated; if insert happened, returns inserted row.
    if (res.rows.length) {
      console.log("Upsert result:", res.rows[0]);
    } else {
      console.log("No rows returned (unexpected).");
    }
    await client.end();
    process.exit(0);
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
