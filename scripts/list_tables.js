const { Client } = require("pg");
(async () => {
  try {
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) { console.error("Missing env: DATABASE_URL"); process.exit(1); }
    const c = new Client({ connectionString: dbUrl });
    await c.connect();
    const res = await c.query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name");
    if (!res.rows.length) { console.log("no tables found in public schema"); }
    else { console.log(res.rows.map(r => r.table_name).join("\n")); }
    await c.end();
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
