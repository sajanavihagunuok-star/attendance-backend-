import React, { useEffect, useState } from 'react'
const KEY = 'app_support_tickets_v1'
const SUPERADMINS_KEY = 'app_super_admins_v1'
const SESSION_KEY = 'app_user_v1'
function read(key) { return JSON.parse(localStorage.getItem(key) || '[]') }
function save(key, list) { localStorage.setItem(key, JSON.stringify(list)) }
function readSession() { try { return JSON.parse(localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY) || 'null') } catch { return null } }

export default function SupportCenter() {
  const [list, setList] = useState([])
  const [filter, setFilter] = useState('all')
  const [session, setSession] = useState(readSession())

  useEffect(() => setList(read(KEY)), [])

  function handleAddTestTicket() {
    // Only allow superadmins (owners generally should not create tickets here per your rule)
    const sa = read(SUPERADMINS_KEY) || []
    if (!session) return alert('Please login')
    const isSuper = sa.some(x => x.email === session.email)
    if (!isSuper) return alert('Only super admins can create test tickets here')
    const t = { id: 't_' + Date.now(), subject: 'Test ticket from SuperAdmin', institute: 'Demo', status: 'open', createdBy: session.email, createdAt: new Date().toISOString() }
    const updated = [t, ...read(KEY)]; save(KEY, updated); setList(updated)
  }

  function handleView(ticket) {
    window.alert(JSON.stringify(ticket, null, 2))
  }

  function toggleStatus(id) {
    const updated = read(KEY).map(t => t.id === id ? { ...t, status: t.status === 'open' ? 'closed' : 'open' } : t)
    save(KEY, updated); setList(updated)
  }

  function filtered() {
    if (filter === 'all') return list
    return list.filter(t => t.status === filter)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Support & Feedback</h3>

      <div style={{ marginBottom: 12 }}>
        <button onClick={handleAddTestTicket} style={{ padding: '8px 12px' }}>Create Test Ticket (Super Admins only)</button>
        <select value={filter} onChange={e => setFilter(e.target.value)} style={{ marginLeft: 8 }}>
          <option value="all">All</option>
          <option value="open">Open</option>
          <option value="closed">Closed</option>
        </select>
      </div>

      {filtered().length === 0 ? <div style={{ color: '#6b7280' }}>No tickets.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Ticket</th><th>Institute</th><th>Status</th><th>Created By</th><th>Action</th>
          </tr></thead>
          <tbody>
            {filtered().map(t => (
              <tr key={t.id}>
                <td style={{ padding: 8 }}>{t.subject}</td>
                <td>{t.institute}</td>
                <td>{t.status}</td>
                <td>{t.createdBy || '-'}</td>
                <td>
                  <button onClick={() => handleView(t)} style={{ marginRight: 8 }}>View</button>
                  <button onClick={() => toggleStatus(t.id)}>{t.status === 'open' ? 'Close' : 'Reopen'}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ marginTop: 12, color: '#6b7280' }}>
        Support tickets are created by super admins. Owners can view and manage statuses.
      </div>
    </div>
  )
}
