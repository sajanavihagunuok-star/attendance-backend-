import React, { useEffect, useState } from 'react'

const KEY = 'app_subscription_status_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '{}') }
function save(obj) { localStorage.setItem(KEY, JSON.stringify(obj)) }

export default function SASubscription() {
  const [status, setStatus] = useState({ plan: 'Demo', expires: '', seats: 0, limit: 25 })
  useEffect(() => {
    const s = read()
    if (s && Object.keys(s).length) setStatus(s)
  }, [])

  function handleSave() {
    save(status); alert('Subscription saved (local demo)')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Subscription Status</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 640 }}>
        <label>Plan name</label>
        <input value={status.plan} onChange={e => setStatus({ ...status, plan: e.target.value })} />
        <label>Expires</label>
        <input type="date" value={status.expires} onChange={e => setStatus({ ...status, expires: e.target.value })} />
        <label>Seats used</label>
        <input type="number" value={status.seats} onChange={e => setStatus({ ...status, seats: parseInt(e.target.value || 0, 10) })} />
        <label>Seat limit</label>
        <input type="number" value={status.limit} onChange={e => setStatus({ ...status, limit: parseInt(e.target.value || 25, 10) })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleSave} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff' }}>Save</button>
      </div>
    </div>
  )
}
