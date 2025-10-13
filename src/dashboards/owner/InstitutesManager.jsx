import React, { useEffect, useState } from 'react'
const KEY = 'app_institutes_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function InstitutesManager() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ name: '', district: '', planId: '' })
  const [query, setQuery] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => setList(read()), [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function handleAdd() {
    if (!form.name.trim()) return show('Institute name required')
    const item = { id: 'inst_' + Date.now(), name: form.name.trim(), district: form.district || '', planId: form.planId || '', usersCount: 0, createdAt: new Date().toISOString() }
    const updated = [item, ...read()]
    save(updated); setList(updated); setForm({ name: '', district: '', planId: '' }); show('Institute added')
  }

  function handleRemove(id) {
    if (!confirm('Remove institute?')) return
    const updated = read().filter(i => i.id !== id)
    save(updated); setList(updated); show('Institute removed')
  }

  function filtered() {
    const q = query.trim().toLowerCase()
    if (!q) return list
    return list.filter(i => (i.name || '').toLowerCase().includes(q) || (i.district || '').toLowerCase().includes(q))
  }

  function exportCSV() {
    const rows = list.map(i => `${i.id},${i.name},${i.district},${i.planId},${i.usersCount}`)
    const csv = ['ID,Name,District,Plan,Users', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'institutes.csv'; a.click(); URL.revokeObjectURL(url)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Institutes</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 760 }}>
        <label>Name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Institute name" />
        <label>District (Sri Lanka)</label>
        <input value={form.district} onChange={e => setForm({ ...form, district: e.target.value })} placeholder="e.g. Colombo" />
        <label>Plan ID</label>
        <input value={form.planId} onChange={e => setForm({ ...form, planId: e.target.value })} placeholder="Plan id (optional)" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAdd} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Institute</button>
        <button onClick={exportCSV} style={{ marginLeft: 8, padding: '8px 12px' }}>Export CSV</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
        <input placeholder="Search by institute name or district" value={query} onChange={e => setQuery(e.target.value)} style={{ padding: 8, flex: 1 }} />
      </div>

      <div>
        {filtered().length === 0 ? <div style={{ color: '#6b7280' }}>No institutes found.</div> : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
              <th style={{ padding: 8 }}>Name</th><th>District</th><th>Plan</th><th>Users</th><th>Action</th>
            </tr></thead>
            <tbody>
              {filtered().map(i => (
                <tr key={i.id}>
                  <td style={{ padding: 8 }}>{i.name}</td>
                  <td>{i.district || '-'}</td>
                  <td>{i.planId || '-'}</td>
                  <td>{i.usersCount || 0}</td>
                  <td>
                    <button onClick={() => window.alert(JSON.stringify(i, null, 2))} style={{ marginRight: 8 }}>View</button>
                    <button onClick={() => handleRemove(i.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
