import React, { useEffect, useState } from 'react'

const KEY = 'app_lecturers_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function SALecturers() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ name: '', email: '' })
  const [msg, setMsg] = useState('')

  useEffect(() => setList(read()), [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function handleAdd() {
    if (!form.name.trim()) return show('Lecturer name required')
    if (!form.email.trim()) return show('Lecturer email required')
    if (read().some(l => l.email === form.email.trim())) return show('Email already exists')
    const item = { id: 'lec_' + Date.now(), name: form.name.trim(), email: form.email.trim(), createdAt: new Date().toISOString() }
    const updated = [item, ...read()]
    save(updated); setList(updated); setForm({ name: '', email: '' }); show('Lecturer added')
  }

  function handleRemove(id) {
    if (!confirm('Remove lecturer?')) return
    const updated = read().filter(l => l.id !== id)
    save(updated); setList(updated); show('Lecturer removed')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Lecturers</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Lecturer name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
        <label>Lecturer email</label>
        <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAdd} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Lecturer</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      {list.length === 0 ? <div style={{ color: '#6b7280' }}>No lecturers yet.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Name</th><th>Email</th><th>Action</th>
          </tr></thead>
          <tbody>
            {list.map(l => (
              <tr key={l.id}>
                <td style={{ padding: 8 }}>{l.name}</td>
                <td>{l.email}</td>
                <td>
                  <button onClick={() => handleRemove(l.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
