// migrate.js
import fs from 'fs'
import { Client } from 'pg'

const DATABASE_URL = process.env.DATABASE_URL
if (!DATABASE_URL) {
  console.error('Set DATABASE_URL environment variable first')
  process.exit(1)
}

const sql = fs.readFileSync('migrate.sql', 'utf8')

async function run() {
  const c = new Client({ connectionString: DATABASE_URL })
  await c.connect()
  try {
    await c.query('BEGIN')
    await c.query(sql)
    await c.query('COMMIT')
    console.log('Migration ran successfully')
  } catch (e) {
    await c.query('ROLLBACK')
    console.error('Migration failed:', e.message)
    process.exit(2)
  } finally {
    await c.end()
  }
}

run()
