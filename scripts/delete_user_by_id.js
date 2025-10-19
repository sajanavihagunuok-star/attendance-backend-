const { Client } = require("pg");
(async () => {
  try {
    const id = process.argv[2];
    const db = process.env.DATABASE_URL;
    if (!id || !db) { console.error("Missing id or DATABASE_URL"); process.exit(1); }
    const c = new Client({ connectionString: db });
    await c.connect();
    const del = await c.query("DELETE FROM public.users WHERE id = $1 RETURNING id, email, role", [id]);
    if (del.rows.length) {
      console.log("deleted:", del.rows[0]);
    } else {
      console.log("no row deleted for id", id);
    }
    const dupCheck = await c.query("SELECT email, count(*) AS cnt FROM public.users GROUP BY email HAVING count(*)>1");
    if (dupCheck.rows.length) {
      console.log("remaining duplicates:");
      dupCheck.rows.forEach(r => console.log(`${r.email} count=${r.cnt}`));
    } else {
      console.log("no duplicate emails remain");
    }
    await c.end();
  } catch (err) {
    console.error("ERROR:", err.message || err);
    process.exit(1);
  }
})();
