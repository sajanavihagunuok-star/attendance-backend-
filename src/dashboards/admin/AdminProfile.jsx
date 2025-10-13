import React, { useEffect, useState } from 'react'

const USER_KEY = 'app_user_v1'
const RADIUS_KEY = 'app_geofence_v1'

function readUser() {
  return JSON.parse(localStorage.getItem(USER_KEY) || '{}')
}
function saveUser(u) {
  localStorage.setItem(USER_KEY, JSON.stringify(u))
}
function readRadius() {
  return JSON.parse(localStorage.getItem(RADIUS_KEY) || '{}')
}
function saveRadius(r) {
  localStorage.setItem(RADIUS_KEY, JSON.stringify(r))
}

export default function AdminProfile() {
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [newPass, setNewPass] = useState('')
  const [confirmPass, setConfirmPass] = useState('')
  const [msg, setMsg] = useState('')
  const [radiusKm, setRadiusKm] = useState(0.5)
  const [geoCenter, setGeoCenter] = useState({ lat: '', lng: '' })

  useEffect(() => {
    const u = readUser()
    setDisplayName(u.displayName || '')
    setEmail(u.email || '')
    const r = readRadius()
    if (r && typeof r.radiusKm !== 'undefined') {
      setRadiusKm(r.radiusKm)
      setGeoCenter({ lat: r.lat || '', lng: r.lng || '' })
    }
  }, [])

  function showMsg(text) {
    setMsg(text)
    setTimeout(() => setMsg(''), 3500)
  }

  function handleSaveProfile() {
    if (!displayName.trim()) return showMsg('Display name required')
    if (!email.trim()) return showMsg('Email required')
    const user = { displayName: displayName.trim(), email: email.trim(), role: 'admin' }
    if (newPass) user.password = newPass
    saveUser(user)
    window.dispatchEvent(new Event('hashchange'))
    setNewPass('')
    setConfirmPass('')
    showMsg('Profile saved')
  }

  function handleResetPassword() {
    if (!newPass) return showMsg('Enter new password to reset')
    if (newPass !== confirmPass) return showMsg('Passwords do not match')
    const u = readUser()
    u.password = newPass
    saveUser(u)
    setNewPass('')
    setConfirmPass('')
    showMsg('Password updated')
  }

  function handleSaveGeofence() {
    const lat = parseFloat(geoCenter.lat)
    const lng = parseFloat(geoCenter.lng)
    const r = parseFloat(radiusKm)
    if (Number.isNaN(lat) || Number.isNaN(lng)) return showMsg('Valid lat and lng required')
    if (Number.isNaN(r) || r <= 0) return showMsg('Radius must be > 0')
    const payload = { lat, lng, radiusKm: r }
    saveRadius(payload)
    showMsg('Geofence saved')
  }

  function handleUseCurrentLocation() {
    if (!navigator.geolocation) return showMsg('Geolocation not supported in this browser')
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setGeoCenter({ lat: String(pos.coords.latitude), lng: String(pos.coords.longitude) })
        showMsg('Current location captured')
      },
      () => showMsg('Unable to retrieve location')
    )
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Admin Profile</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '180px 1fr', maxWidth: 720 }}>
        <label>Display Name</label>
        <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Admin name" />

        <label>Email</label>
        <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" />

        <label>New Password</label>
        <input type="password" value={newPass} onChange={(e) => setNewPass(e.target.value)} placeholder="Leave blank to keep" />

        <label>Confirm Password</label>
        <input type="password" value={confirmPass} onChange={(e) => setConfirmPass(e.target.value)} placeholder="Repeat new password" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleSaveProfile} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
          Save Profile
        </button>
        <button onClick={handleResetPassword} style={{ marginLeft: 8, padding: '8px 12px' }}>
          Reset Password
        </button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      <h4>Geofence Settings</h4>
      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '180px 1fr', maxWidth: 720 }}>
        <label>Center Latitude</label>
        <input value={geoCenter.lat} onChange={(e) => setGeoCenter({ ...geoCenter, lat: e.target.value })} placeholder="e.g. 6.9271" />

        <label>Center Longitude</label>
        <input value={geoCenter.lng} onChange={(e) => setGeoCenter({ ...geoCenter, lng: e.target.value })} placeholder="e.g. 79.8612" />

        <label>Radius (km)</label>
        <input type="number" step="0.1" value={radiusKm} onChange={(e) => setRadiusKm(e.target.value)} placeholder="0.5" />

        <div style={{ gridColumn: '1 / -1' }}>
          <button onClick={handleUseCurrentLocation} style={{ padding: '8px 12px', marginRight: 8 }}>Use Current Location</button>
          <button onClick={handleSaveGeofence} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Save Geofence</button>
        </div>
      </div>

      <div style={{ marginTop: 12, fontSize: 13, color: '#6b7280' }}>
        Geofence settings are stored locally. When a session enforces geolocation, students must be within this radius to mark attendance.
      </div>
    </div>
  )
}
