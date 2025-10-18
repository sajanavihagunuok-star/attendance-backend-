require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on("error", (err) => {
  console.error("[pool][ERROR] Unexpected error on idle client", err && err.message ? err.message : err);
});

(async () => {
  let client;
  try {
    client = await pool.connect();
    console.log("connected");
    const res = await client.query("SELECT current_database() AS db, current_user AS user, version() AS ver;");
    console.table(res.rows);
    const now = await client.query("SELECT now() as now;");
    console.log("now:", now.rows[0].now);
  } catch (err) {
    console.error("[db][ERROR]", err);
  } finally {
    if (client) client.release();
    try { await pool.end(); console.log("pool closed"); } catch (e) { console.error("[pool][END][ERROR]", e); }
  }
})();
