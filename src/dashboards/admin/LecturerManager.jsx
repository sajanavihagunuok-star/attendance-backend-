import React, { useEffect, useState } from 'react'

const LECTURERS_KEY = 'app_lecturers_v1'

function readLecturers() {
  return JSON.parse(localStorage.getItem(LECTURERS_KEY) || '[]')
}
function saveLecturers(list) {
  localStorage.setItem(LECTURERS_KEY, JSON.stringify(list))
}

export default function LecturerManager() {
  const [list, setList] = useState([])
  const [form, setForm] = useState({ name: '', email: '' })
  const [editingId, setEditingId] = useState(null)
  const [query, setQuery] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    setList(readLecturers())
  }, [])

  function showMsg(text) {
    setMsg(text)
    setTimeout(() => setMsg(''), 3000)
  }

  function resetForm() {
    setEditingId(null)
    setForm({ name: '', email: '' })
  }

  function validate() {
    if (!form.name.trim()) return 'Name required'
    if (!form.email.trim()) return 'Email required'
    const re = /\S+@\S+\.\S+/
    if (!re.test(form.email)) return 'Enter a valid email'
    return null
  }

  function handleAddOrUpdate() {
    const err = validate()
    if (err) return showMsg(err)
    const current = readLecturers()
    if (editingId) {
      const updated = current.map(l => (l.id === editingId ? { ...l, ...form } : l))
      saveLecturers(updated)
      setList(updated)
      showMsg('Lecturer updated')
    } else {
      if (current.some(l => l.email === form.email)) return showMsg('Email already exists')
      const item = { id: 'lec_' + Date.now(), name: form.name.trim(), email: form.email.trim(), createdAt: new Date().toISOString() }
      const updated = [item, ...current]
      saveLecturers(updated)
      setList(updated)
      showMsg('Lecturer added')
    }
    resetForm()
  }

  function handleEdit(lec) {
    setEditingId(lec.id)
    setForm({ name: lec.name, email: lec.email })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function handleRemove(id) {
    if (!confirm('Remove this lecturer?')) return
    const updated = readLecturers().filter(l => l.id !== id)
    saveLecturers(updated)
    setList(updated)
    showMsg('Lecturer removed')
  }

  function filtered() {
    const q = query.trim().toLowerCase()
    if (!q) return list
    return list.filter(l => (l.name || '').toLowerCase().includes(q) || (l.email || '').toLowerCase().includes(q))
  }

  function exportCSV() {
    const rows = list.map(l => `${l.name},${l.email}`)
    const csv = ['Name,Email', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'lecturers.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  function importCSV(text) {
    const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
    const parsed = []
    for (let i = 0; i < lines.length; i++) {
      const cols = lines[i].split(',').map(c => c.trim())
      if (cols.length < 2) continue
      const [name, email] = cols
      if (!name || !email) continue
      parsed.push({ id: 'lec_' + Date.now() + '_' + i, name, email, createdAt: new Date().toISOString() })
    }
    if (parsed.length === 0) return showMsg('No valid rows found')
    const combined = [...parsed, ...readLecturers()]
    saveLecturers(combined)
    setList(combined)
    showMsg(`Imported ${parsed.length} lecturers`)
  }

  function handleCSVFile(e) {
    const file = e.target.files && e.target.files[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      importCSV(ev.target.result)
      e.target.value = ''
    }
    reader.readAsText(file)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Manage Lecturers</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Lecturer Name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Full name" />

        <label>Lecturer Email</label>
        <input value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} placeholder="email@example.com" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAddOrUpdate} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
          {editingId ? 'Update Lecturer' : 'Add Lecturer'}
        </button>
        <button onClick={resetForm} style={{ marginLeft: 8, padding: '8px 12px' }}>Clear</button>

        <label style={{ marginLeft: 12, cursor: 'pointer' }}>
          <input type="file" accept=".csv" onChange={handleCSVFile} style={{ display: 'none' }} />
          <span style={{ padding: '8px 12px', marginLeft: 6, border: '1px solid #ddd', borderRadius: 6 }}>Import CSV</span>
        </label>

        <button onClick={exportCSV} style={{ marginLeft: 8, padding: '8px 12px' }}>Export CSV</button>

        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
        <input placeholder="Search by name or email" value={query} onChange={e => setQuery(e.target.value)} style={{ padding: 8, flex: 1 }} />
      </div>

      <div>
        {filtered().length === 0 ? (
          <div style={{ color: '#6b7280' }}>No lecturers found.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
                <th style={{ padding: 8 }}>Name</th>
                <th>Email</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered().map(l => (
                <tr key={l.id}>
                  <td style={{ padding: 8 }}>{l.name}</td>
                  <td>{l.email}</td>
                  <td>
                    <button onClick={() => handleEdit(l)} style={{ marginRight: 8 }}>Edit</button>
                    <button onClick={() => handleRemove(l.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px', borderRadius: 4 }}>
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div style={{ marginTop: 12, fontSize: 13, color: '#6b7280' }}>
        Lecturer data is stored locally for now. Replace localStorage calls with API endpoints when integrating with your backend.
      </div>
    </div>
  )
}
