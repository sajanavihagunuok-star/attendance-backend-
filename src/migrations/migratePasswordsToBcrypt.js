// src/migrations/migratePasswordsToBcrypt.js
// Run this file from the browser console (copy-paste) to migrate all known user stores to bcrypt hashes.
// Example usage: open devtools console and paste:
//   (async()=>{ const res = await window.migratePasswordsToBcrypt(); console.log(res); })()

importScriptsIfNeeded()

function importScriptsIfNeeded() {
  // no-op placeholder for bundlers; this file is intended to be copy-pasted at runtime in console
}

// Expose a migration function on window so you can run it from DevTools
window.migratePasswordsToBcrypt = async function() {
  // keys to migrate (match your app)
  const stores = ['app_owner_user_v1', 'app_super_admins_v1', 'app_admins_v1', 'app_lecturers_v1']
  const results = []
  for (const key of stores) {
    const raw = localStorage.getItem(key)
    if (!raw) { results.push({ key, status: 'no-data' }); continue }
    try {
      const data = JSON.parse(raw)
      if (Array.isArray(data)) {
        // array of users
        const updated = []
        for (const u of data) {
          if (!u.password) {
            updated.push(u)
            continue
          }
          if (typeof u.password === 'string' && u.password.startsWith('$2')) {
            // already bcrypt hashed
            updated.push(u)
            continue
          }
          // hash and replace
          // use bcryptjs via CDN loaded into page
          const hash = await window._bcryptHash(u.password)
          updated.push({ ...u, password: hash, passwordVersion: 1 })
        }
        localStorage.setItem(key, JSON.stringify(updated))
        results.push({ key, migrated: updated.length })
      } else if (typeof data === 'object' && data !== null) {
        const u = data
        if (u.password && !(typeof u.password === 'string' && u.password.startsWith('$2'))) {
          const hash = await window._bcryptHash(u.password)
          const out = { ...u, password: hash, passwordVersion: 1 }
          localStorage.setItem(key, JSON.stringify(out))
          results.push({ key, migrated: 1 })
        } else {
          results.push({ key, migrated: 0 })
        }
      } else {
        results.push({ key, status: 'unknown-format' })
      }
    } catch (e) {
      results.push({ key, error: e.message })
    }
  }
  return results
}
