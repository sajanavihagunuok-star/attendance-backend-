const { Client } = require("pg");
(async () => {
  try {
    const db = process.env.DATABASE_URL;
    if (!db) { console.error("Missing env: DATABASE_URL"); process.exit(1); }
    const c = new Client({ connectionString: db });
    await c.connect();
    const res = await c.query("SELECT indexname, indexdef FROM pg_indexes WHERE schemaname='public' AND tablename='users'");
    res.rows.forEach(r => console.log(r.indexname + "  |  " + r.indexdef));
    await c.end();
  } catch (err) {
    console.error('ERROR:', err.message || err);
    process.exit(1);
  }
})();
