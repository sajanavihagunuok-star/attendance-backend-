import React, { useEffect, useState } from 'react'
const KEY = 'app_super_admins_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function SuperAdminManager() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ name: '', email: '' })
  const [msg, setMsg] = useState('')

  useEffect(() => setList(read()), [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function handleAdd() {
    if (!form.name.trim()) return show('Name required')
    if (!form.email.trim()) return show('Email required')
    const item = { id: 'sa_' + Date.now(), name: form.name.trim(), email: form.email.trim(), createdAt: new Date().toISOString() }
    const updated = [item, ...read()]
    save(updated); setList(updated); setForm({ name: '', email: '' }); show('Super admin added')
  }

  function handleRemove(id) {
    if (!confirm('Remove super admin?')) return
    const updated = read().filter(s => s.id !== id)
    save(updated); setList(updated); show('Removed')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Super Admins</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        <label>Email</label>
        <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAdd} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Super Admin</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      {list.length === 0 ? <div style={{ color: '#6b7280' }}>No super admins.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Name</th><th>Email</th><th>Action</th>
          </tr></thead>
          <tbody>
            {list.map(s => (
              <tr key={s.id}>
                <td style={{ padding: 8 }}>{s.name}</td>
                <td>{s.email}</td>
                <td><button onClick={() => handleRemove(s.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
