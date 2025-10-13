import React, { useEffect, useState } from 'react'
const KEY = 'app_support_tickets_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function SATickets() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ subject: '', details: '' })

  useEffect(() => setList(read()), [])

  function create() {
    if (!form.subject.trim()) return alert('Subject required')
    const t = { id: 't_' + Date.now(), subject: form.subject.trim(), details: form.details.trim(), status: 'open', createdAt: new Date().toISOString(), createdBy: 'superadmin' }
    const updated = [t, ...read()]; save(updated); setList(updated); setForm({ subject: '', details: '' })
  }

  function toggle(id) {
    const updated = read().map(t => t.id === id ? { ...t, status: t.status === 'open' ? 'closed' : 'open' } : t)
    save(updated); setList(updated)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Support Tickets</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 720 }}>
        <label>Subject</label>
        <input value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} />
        <label>Details</label>
        <input value={form.details} onChange={e => setForm({ ...form, details: e.target.value })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={create} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff' }}>Create Ticket</button>
      </div>

      <hr style={{ margin: '18px 0' }} />

      {list.length === 0 ? <div style={{ color: '#6b7280' }}>No tickets.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Subject</th><th>Details</th><th>Status</th><th>Action</th>
          </tr></thead>
          <tbody>
            {list.map(t => (
              <tr key={t.id}>
                <td style={{ padding: 8 }}>{t.subject}</td>
                <td>{t.details}</td>
                <td>{t.status}</td>
                <td>
                  <button onClick={() => toggle(t.id)} style={{ marginRight: 8 }}>{t.status === 'open' ? 'Close' : 'Reopen'}</button>
                  <button onClick={() => window.alert(JSON.stringify(t, null, 2))}>View</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
