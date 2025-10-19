const { Client } = require("pg");
(async () => {
  try {
    const c = new Client({ connectionString: process.env.DATABASE_URL });
    await c.connect();
    const r1 = await c.query("SELECT count(*) AS cnt FROM public.users");
    const r2 = await c.query("SELECT version()");
    console.log("user_count:", r1.rows[0].cnt);
    console.log("pg_version:", r2.rows[0].version);
    await c.end();
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
