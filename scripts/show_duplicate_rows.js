const { Client } = require("pg");
(async () => {
  try {
    const db = process.env.DATABASE_URL;
    if (!db) { console.error("Missing env: DATABASE_URL"); process.exit(1); }
    const c = new Client({ connectionString: db });
    await c.connect();
    const dupEmailsRes = await c.query("SELECT email FROM public.users GROUP BY email HAVING count(*)>1");
    if (!dupEmailsRes.rows.length) { console.log("no duplicate emails"); await c.end(); return; }
    for (const r of dupEmailsRes.rows) {
      console.log('--- duplicate email:', r.email, '---');
      const rows = await c.query("SELECT id, email, name, created_at, role FROM public.users WHERE email=$1 ORDER BY created_at ASC", [r.email]);
      rows.rows.forEach(rr => console.log(JSON.stringify(rr)));
    }
    await c.end();
  } catch (err) { console.error("ERROR:", err.message || err); process.exit(1); }
})();
