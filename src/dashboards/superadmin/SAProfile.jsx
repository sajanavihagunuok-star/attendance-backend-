import React, { useEffect, useState } from 'react'

const SESSION_KEY = 'app_user_v1'
const SUPERADMINS_KEY = 'app_super_admins_v1'

function readSession() { try { return JSON.parse(localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY) || 'null') } catch { return null } }
function readSuperAdmins() { try { return JSON.parse(localStorage.getItem(SUPERADMINS_KEY) || '[]') } catch { return [] } }
function saveSuperAdmins(list) { localStorage.setItem(SUPERADMINS_KEY, JSON.stringify(list)) }

export default function SAProfile() {
  const session = readSession()
  const [profile, setProfile] = useState({ name: '', email: '' })
  const [newPass, setNewPass] = useState('')
  const [confirm, setConfirm] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    if (!session) return
    const sa = readSuperAdmins().find(s => s.email === session.email) || {}
    setProfile({ name: sa.name || session.displayName || '', email: sa.email || session.email || '' })
  }, [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function saveProfile() {
    if (!profile.name.trim()) return show('Name required')
    if (!profile.email.trim()) return show('Email required')
    const list = readSuperAdmins()
    const idx = list.findIndex(s => s.email === profile.email)
    if (idx >= 0) { list[idx] = { ...list[idx], name: profile.name, email: profile.email }; saveSuperAdmins(list); show('Profile saved'); return }
    show('Profile saved (local)')
  }

  function resetPassword() {
    if (!newPass) return show('Enter new password')
    if (newPass !== confirm) return show('Passwords do not match')
    const list = readSuperAdmins()
    const idx = list.findIndex(s => s.email === profile.email)
    if (idx >= 0) { list[idx].password = newPass; saveSuperAdmins(list); setNewPass(''); setConfirm(''); show('Password updated'); return }
    show('Password updated (local)')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Super Admin Profile</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '180px 1fr', maxWidth: 720 }}>
        <label>Name</label>
        <input value={profile.name} onChange={e => setProfile({ ...profile, name: e.target.value })} />
        <label>Email</label>
        <input value={profile.email} onChange={e => setProfile({ ...profile, email: e.target.value })} />
        <label>New Password</label>
        <input type="password" value={newPass} onChange={e => setNewPass(e.target.value)} />
        <label>Confirm Password</label>
        <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={saveProfile} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff' }}>Save Profile</button>
        <button onClick={resetPassword} style={{ marginLeft: 8, padding: '8px 12px' }}>Reset Password</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>
      <div style={{ marginTop: 12, color: '#6b7280' }}>Only reset for demo kiosk & hub link for production.</div>
    </div>
  )
}
