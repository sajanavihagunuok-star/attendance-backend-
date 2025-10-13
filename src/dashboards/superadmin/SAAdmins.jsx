import React, { useEffect, useState } from 'react'

const KEY = 'app_admins_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function SAAdmins() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ name: '', email: '', password: '' })
  const [msg, setMsg] = useState('')

  useEffect(() => setList(read()), [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function handleAdd() {
    if (!form.name.trim()) return show('Name required')
    if (!form.email.trim()) return show('Email required')
    if (!form.password) return show('Password required')
    if (read().some(a => a.email === form.email.trim())) return show('Email already exists')
    const item = { id: 'adm_' + Date.now(), name: form.name.trim(), email: form.email.trim(), password: form.password, createdAt: new Date().toISOString() }
    const updated = [item, ...read()]
    save(updated); setList(updated); setForm({ name: '', email: '', password: '' }); show('Admin added')
  }

  function handleRemove(id) {
    if (!confirm('Remove admin?')) return
    const updated = read().filter(a => a.id !== id)
    save(updated); setList(updated); show('Admin removed')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Admins</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Admin name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        <label>Admin email</label>
        <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
        <label>Password</label>
        <input type="password" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAdd} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Admin</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      {list.length === 0 ? <div style={{ color: '#6b7280' }}>No admins yet.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Name</th><th>Email</th><th>Action</th>
          </tr></thead>
          <tbody>
            {list.map(a => (
              <tr key={a.id}>
                <td style={{ padding: 8 }}>{a.name}</td>
                <td>{a.email}</td>
                <td><button onClick={() => handleRemove(a.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>Remove</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
