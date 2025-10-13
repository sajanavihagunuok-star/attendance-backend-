import React, { useEffect, useState } from 'react'
const USER_KEY = 'app_user_v1'
function readUser() { return JSON.parse(localStorage.getItem(USER_KEY) || '{}') }
function saveUser(u) { localStorage.setItem(USER_KEY, JSON.stringify(u)) }

export default function OwnerProfile() {
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [newPass, setNewPass] = useState('')
  const [confirmPass, setConfirmPass] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    const u = readUser(); setDisplayName(u.displayName || ''); setEmail(u.email || '')
  }, [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function save() {
    if (!displayName.trim()) return show('Display name required')
    if (!email.trim()) return show('Email required')
    if (newPass && newPass !== confirmPass) return show('Passwords do not match')
    const u = { displayName: displayName.trim(), email: email.trim(), role: 'owner' }
    if (newPass) u.password = newPass
    saveUser(u); window.dispatchEvent(new Event('hashchange')); setNewPass(''); setConfirmPass(''); show('Profile saved')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Owner Profile</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '180px 1fr', maxWidth: 720 }}>
        <label>Name</label>
        <input value={displayName} onChange={e => setDisplayName(e.target.value)} />
        <label>Email</label>
        <input value={email} onChange={e => setEmail(e.target.value)} />
        <label>New Password</label>
        <input type="password" value={newPass} onChange={e => setNewPass(e.target.value)} />
        <label>Confirm Password</label>
        <input type="password" value={confirmPass} onChange={e => setConfirmPass(e.target.value)} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={save} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Save Profile</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>
    </div>
  )
}
