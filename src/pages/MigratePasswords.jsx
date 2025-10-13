// src/pages/MigratePasswords.jsx
import React, { useEffect, useState } from 'react'
import { hashPasswordSync } from '../utils/bcryptHelper'

/*
  In-browser migration UI (development only).
  Visit #/migrate after starting the dev server to migrate existing plain-text passwords
  to bcrypt hashes in these keys:
    - app_owner_user_v1 (single object)
    - app_super_admins_v1 (array)
    - app_admins_v1 (array)
    - app_lecturers_v1 (array)

  The page will replace any plain-text password that is not already a bcrypt hash.
*/

const STORE_KEYS = ['app_owner_user_v1', 'app_super_admins_v1', 'app_admins_v1', 'app_lecturers_v1']

function isBcryptHash(s) {
  return typeof s === 'string' && s.startsWith('$2')
}

function read(key) {
  try { return JSON.parse(localStorage.getItem(key) || 'null') } catch { return null }
}
function write(key, v) {
  localStorage.setItem(key, JSON.stringify(v))
}

export default function MigratePasswords() {
  const [log, setLog] = useState([])
  const [running, setRunning] = useState(false)

  function append(msg) {
    setLog(l => [msg, ...l])
  }

  async function runMigration() {
    if (running) return
    setRunning(true)
    append('Starting migration...')
    for (const key of STORE_KEYS) {
      const raw = read(key)
      if (!raw) {
        append(`${key}: no data found`)
        continue
      }
      try {
        if (Array.isArray(raw)) {
          let changed = 0
          const updated = raw.map(u => {
            if (!u || typeof u !== 'object') return u
            if (!u.password) return u
            if (isBcryptHash(u.password)) return u
            const hashed = hashPasswordSync(String(u.password))
            changed++
            return { ...u, password: hashed, passwordVersion: 1 }
          })
          write(key, updated)
          append(`${key}: migrated ${changed} user(s)`)
        } else if (typeof raw === 'object' && raw !== null) {
          const u = raw
          if (!u.password) {
            append(`${key}: no password field`)
          } else if (isBcryptHash(u.password)) {
            append(`${key}: already hashed`)
          } else {
            const hashed = hashPasswordSync(String(u.password))
            const out = { ...u, password: hashed, passwordVersion: 1 }
            write(key, out)
            append(`${key}: migrated single user`)
          }
        } else {
          append(`${key}: unknown format`)
        }
      } catch (e) {
        append(`${key}: error ${e.message}`)
      }
    }
    append('Migration complete.')
    setRunning(false)
  }

  // safety: warn user if not in localhost or dev environment
  const unsafeHost = typeof window !== 'undefined' && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1'

  return (
    <div style={{ padding: 20 }}>
      <h2>Password Migration (dev only)</h2>
      {unsafeHost && (
        <div style={{ color: '#b91c1c', marginBottom: 12 }}>
          Warning: You are not on localhost. Only run this migration on local development builds.
        </div>
      )}
      <div style={{ marginBottom: 12 }}>
        <button onClick={runMigration} disabled={running || unsafeHost} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
          Run migration now
        </button>
        <button onClick={() => { setLog([]) }} style={{ marginLeft: 8, padding: '8px 12px' }}>Clear log</button>
      </div>

      <div style={{ maxHeight: 360, overflow: 'auto', border: '1px solid #eee', padding: 12, borderRadius: 6, background: '#fff' }}>
        {log.length === 0 ? <div style={{ color: '#6b7280' }}>No output yet.</div> : log.map((l, i) => <div key={i} style={{ fontFamily: 'monospace', marginBottom: 6 }}>{l}</div>)}
      </div>

      <div style={{ marginTop: 12, color: '#6b7280' }}>
        After migration, the Login page will verify passwords against bcrypt hashes. Do not run this on production.
      </div>
    </div>
  )
}
