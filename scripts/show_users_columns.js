const { Client } = require("pg");
(async () => {
  try {
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) { console.error("Missing env: DATABASE_URL"); process.exit(1); }
    const c = new Client({ connectionString: dbUrl });
    await c.connect();
    const res = await c.query(
      "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
      ["users"]
    );
    if (!res.rows.length) {
      console.log("no 'users' table found in public schema");
    } else {
      console.log("users table columns:");
      res.rows.forEach(r => console.log(`${r.column_name} \t ${r.data_type}`));
    }
    await c.end();
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
