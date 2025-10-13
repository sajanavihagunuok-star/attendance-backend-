import React, { useEffect, useState } from 'react'
import { verifyPasswordSync } from '../utils/bcryptHelper' // <- must match exported name

const SESSION_KEY = 'app_user_v1'
const OWNER_KEY = 'app_owner_user_v1'
const SUPERADMINS_KEY = 'app_super_admins_v1'
const ADMINS_KEY = 'app_admins_v1'
const LECTURERS_KEY = 'app_lecturers_v1'

function readArray(key) {
  try { return JSON.parse(localStorage.getItem(key) || '[]') } catch { return [] }
}
function readObject(key) {
  try { return JSON.parse(localStorage.getItem(key) || 'null') } catch { return null }
}

function isBcryptHash(s) { return typeof s === 'string' && s.startsWith('$2') }

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [remember, setRemember] = useState(true)
  const [hasData, setHasData] = useState(false)

  useEffect(() => {
    const any =
      !!readObject(OWNER_KEY) ||
      readArray(SUPERADMINS_KEY).length > 0 ||
      readArray(ADMINS_KEY).length > 0 ||
      readArray(LECTURERS_KEY).length > 0
    setHasData(!!any)
  }, [])

  function showError(msg) {
    setError(msg)
    setTimeout(() => setError(''), 4000)
  }

  function persistSession(userObj) {
    const session = {
      id: userObj.id || ('u_' + Date.now()),
      displayName: userObj.name || userObj.displayName || userObj.email,
      email: userObj.email,
      role: userObj.role || 'student'
    }
    try {
      if (remember) {
        localStorage.setItem(SESSION_KEY, JSON.stringify(session))
        sessionStorage.removeItem(SESSION_KEY)
      } else {
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(session))
        localStorage.removeItem(SESSION_KEY)
      }
    } catch (e) {
      console.error('session persist error', e)
    }
  }

  async function handleLogin(e) {
    e && e.preventDefault()
    if (!email.trim()) return showError('Email required')
    if (!password) return showError('Password required')

    // owner
    const owner = readObject(OWNER_KEY)
    if (owner && owner.email === email.trim()) {
      const ok = isBcryptHash(owner.password) ? verifyPasswordSync(password, owner.password) : password === owner.password
      if (ok) { persistSession({ id: owner.id, name: owner.name, email: owner.email, role: 'owner' }); window.location.hash = '#/dashboard/owner'; return }
      else return showError('Invalid credentials')
    }

    // superadmins
    const sas = readArray(SUPERADMINS_KEY)
    const foundSA = sas.find(s => s.email === email.trim())
    if (foundSA) {
      const ok = isBcryptHash(foundSA.password) ? verifyPasswordSync(password, foundSA.password) : password === foundSA.password
      if (ok) { persistSession({ id: foundSA.id, name: foundSA.name, email: foundSA.email, role: 'superadmin' }); window.location.hash = '#/dashboard/superadmin'; return }
      else return showError('Invalid credentials')
    }

    // admins
    const admins = readArray(ADMINS_KEY)
    const foundAdmin = admins.find(a => a.email === email.trim())
    if (foundAdmin) {
      const ok = isBcryptHash(foundAdmin.password) ? verifyPasswordSync(password, foundAdmin.password) : password === foundAdmin.password
      if (ok) { persistSession({ id: foundAdmin.id, name: foundAdmin.name, email: foundAdmin.email, role: 'admin' }); window.location.hash = '#/dashboard/admin'; return }
      else return showError('Invalid credentials')
    }

    // lecturers
    const lecturers = readArray(LECTURERS_KEY)
    const foundL = lecturers.find(l => l.email === email.trim())
    if (foundL) {
      const ok = isBcryptHash(foundL.password) ? verifyPasswordSync(password, foundL.password) : password === foundL.password
      if (ok) { persistSession({ id: foundL.id, name: foundL.name, email: foundL.email, role: 'lecturer' }); window.location.hash = '#/dashboard/lecturer'; return }
      else return showError('Invalid credentials')
    }

    showError('Invalid credentials. If this is a development environment, create test accounts or run migration.')
  }

  // helper to create unhashed test accounts (fast) or hashed via migration page
  function createTestAccounts() {
    const owner = { id: 'owner_1', name: 'Owner Sijana', email: 'owner@example.com', password: 'ownerpass', role: 'owner' }
    const sa = { id: 'sa_1', name: 'Hari', email: 'hari@example.com', password: 'superpass', role: 'superadmin' }
    const adm = { id: 'adm_1', name: 'Admin Sigma', email: 'admin@example.com', password: 'adminpass', role: 'admin' }
    const lec = { id: 'lec_1', name: 'Lecturer One', email: 'lecturer@example.com', password: 'lectpass', role: 'lecturer' }

    localStorage.setItem(OWNER_KEY, JSON.stringify(owner))
    localStorage.setItem(SUPERADMINS_KEY, JSON.stringify([sa]))
    localStorage.setItem(ADMINS_KEY, JSON.stringify([adm]))
    localStorage.setItem(LECTURERS_KEY, JSON.stringify([lec]))
    setHasData(true)
    showError('Test accounts created (plain-text). For production, run migration page to hash passwords.')
  }

  return (
    <div style={{ padding: 20, maxWidth: 720 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0 }}>Sign in</h2>
        <button onClick={() => { window.location.hash = '#/'; }} style={{ padding: '6px 10px' }}>Back</button>
      </div>

      <form onSubmit={handleLogin} style={{ display: 'grid', gap: 8, marginTop: 12 }}>
        <label>Email</label>
        <input value={email} onChange={e => setEmail(e.target.value)} placeholder="email@example.com" />

        <label>Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="password" />

        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} />
            <span>Remember</span>
          </label>

          <button type="submit" style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
            Sign In
          </button>

          <button type="button" onClick={() => { setEmail(''); setPassword(''); }} style={{ padding: '8px 12px' }}>
            Clear
          </button>
        </div>

        {error && <div style={{ marginTop: 8, color: '#ef4444' }}>{error}</div>}
      </form>

      <hr style={{ margin: '18px 0' }} />

      <div style={{ color: '#6b7280' }}>
        Developer helpers:
        <div style={{ marginTop: 8 }}>
          <button onClick={createTestAccounts} style={{ padding: '8px 12px', marginRight: 8 }}>Create test accounts</button>
          <button onClick={() => {
            localStorage.removeItem(OWNER_KEY); localStorage.removeItem(SUPERADMINS_KEY); localStorage.removeItem(ADMINS_KEY); localStorage.removeItem(LECTURERS_KEY);
            localStorage.removeItem(SESSION_KEY); sessionStorage.removeItem(SESSION_KEY); setHasData(false); showError('Test data cleared')
          }} style={{ padding: '8px 12px' }}>
            Clear test data
          </button>
        </div>

        <div style={{ marginTop: 12 }}>
          To migrate existing plain-text passwords to bcrypt: go to #/migrate and click Run migration.
        </div>

        {!hasData && <div style={{ marginTop: 12, color: '#b91c1c' }}>No saved users found. Create test accounts or run migration.</div>}
      </div>
    </div>
  )
}
