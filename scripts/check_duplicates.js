const { Client } = require("pg");
(async () => {
  try {
    const db = process.env.DATABASE_URL;
    if (!db) { console.error("Missing env: DATABASE_URL"); process.exit(1); }
    const c = new Client({ connectionString: db });
    await c.connect();
    const res = await c.query("SELECT email, count(*) AS cnt FROM public.users GROUP BY email HAVING count(*)>1");
    if (res.rows.length) {
      console.log("duplicates found:");
      res.rows.forEach(r => console.log(`${r.email}  count=${r.cnt}`));
    } else {
      console.log("no duplicate emails found");
    }
    await c.end();
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
