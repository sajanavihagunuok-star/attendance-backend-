import React, { useEffect, useState } from 'react'

const KEY = 'app_coowners_v1'
const SESSION_KEY = 'app_user_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }
function readSession() { try { return JSON.parse(localStorage.getItem(SESSION_KEY) || sessionStorage.getItem(SESSION_KEY) || 'null') } catch { return null } }

export default function CoOwnersManager() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ name: '', email: '' })
  const [msg, setMsg] = useState('')
  const [session, setSession] = useState(readSession())

  useEffect(() => {
    setList(read())
    setSession(readSession())
  }, [])

  function show(t) {
    setMsg(t)
    setTimeout(() => setMsg(''), 3000)
  }

  function add() {
    if (!form.name.trim() || !form.email.trim()) return alert('Name and email required')
    const item = { id: 'co_' + Date.now(), name: form.name.trim(), email: form.email.trim(), createdBy: session?.id || 'owner', createdAt: new Date().toISOString() }
    const updated = [item, ...read()]; save(updated); setList(updated); setForm({ name: '', email: '' }); show('Co-owner added')
  }

  function remove(id) {
    const target = list.find(x => x.id === id)
    if (!target) return
    // only allow removal by the owner who added them (createdBy === current session id)
    if (!session) return alert('No session')
    if (target.createdBy !== session.id) return alert('You cannot remove this co-owner. Only the owner who added them can remove.')
    if (!confirm('Remove co-owner?')) return
    const updated = read().filter(x => x.id !== id); save(updated); setList(updated); show('Co-owner removed')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Co Owners</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        <label>Email</label>
        <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={add} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Co-owner</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      {list.length === 0 ? <div style={{ color: '#6b7280' }}>No co-owners.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Name</th><th>Email</th><th>Added By</th><th>Action</th>
          </tr></thead>
          <tbody>
            {list.map(c => (
              <tr key={c.id}>
                <td style={{ padding: 8 }}>{c.name}</td>
                <td>{c.email}</td>
                <td>{c.createdBy === (session?.id) ? 'You' : c.createdBy}</td>
                <td>
                  <button onClick={() => remove(c.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ marginTop: 12, color: '#6b7280' }}>
        Co-owners have almost the same dashboard as the owner but cannot remove the owner who created them. Future: add role-scoped editors and supporters.
      </div>
    </div>
  )
}
