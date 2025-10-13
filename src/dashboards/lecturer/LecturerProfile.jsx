import React, { useEffect, useState } from 'react'
import { hashPasswordSync, verifyPasswordSync } from '../../utils/bcryptHelper'

const USER_KEY = 'app_user_v1'
function readSession() { try { return JSON.parse(localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY) || 'null') } catch { return null } }

export default function LecturerProfile() {
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [current, setCurrent] = useState('')
  const [npass, setNpass] = useState('')
  const [cpass, setCpass] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    const s = readSession() || {}
    setDisplayName(s.displayName || '')
    setEmail(s.email || '')
  }, [])

  function show(m) { setMsg(m); setTimeout(() => setMsg(''), 3000) }

  function save() {
    if (npass) {
      if (npass !== cpass) return show('New passwords do not match')
      const stored = JSON.parse(localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY) || 'null')
      const storedPass = stored && stored.password
      if (storedPass) {
        const ok = storedPass.startsWith('$2') ? verifyPasswordSync(current, storedPass) : (current === storedPass)
        if (!ok) return show('Current password incorrect')
      }
      const hashed = hashPasswordSync(npass)
      const updated = { ...(stored || {}), displayName, email, password: hashed, passwordVersion: 1 }
      if (localStorage.getItem(USER_KEY)) localStorage.setItem(USER_KEY, JSON.stringify(updated))
      else sessionStorage.setItem(USER_KEY, JSON.stringify(updated))
    } else {
      const stored = JSON.parse(localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY) || 'null') || {}
      const updated = { ...stored, displayName, email }
      if (localStorage.getItem(USER_KEY)) localStorage.setItem(USER_KEY, JSON.stringify(updated))
      else sessionStorage.setItem(USER_KEY, JSON.stringify(updated))
    }
    // sync app_user_v1 session
    const sess = { id: Date.now().toString(), displayName, email, role: 'lecturer' }
    localStorage.setItem('app_user_v1', JSON.stringify(sess))
    show('Profile saved')
    setCurrent(''); setNpass(''); setCpass('')
  }

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>Profile</h3>
      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Display Name</label>
        <input value={displayName} onChange={e => setDisplayName(e.target.value)} />
        <label>Email</label>
        <input value={email} onChange={e => setEmail(e.target.value)} />
        <label>Current Password</label>
        <input type="password" value={current} onChange={e => setCurrent(e.target.value)} />
        <label>New Password</label>
        <input type="password" value={npass} onChange={e => setNpass(e.target.value)} />
        <label>Confirm Password</label>
        <input type="password" value={cpass} onChange={e => setCpass(e.target.value)} />
      </div>
      {msg && <div style={{ marginTop: 12, color: '#10b981' }}>{msg}</div>}
      <div style={{ marginTop: 12 }}>
        <button onClick={save} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Save</button>
      </div>
    </div>
  )
}
