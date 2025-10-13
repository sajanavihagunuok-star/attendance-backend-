import React, { useEffect, useState } from 'react'

const COURSES_KEY = 'app_courses_v1'

function readCourses() {
  return JSON.parse(localStorage.getItem(COURSES_KEY) || '[]')
}
function saveCourses(list) {
  localStorage.setItem(COURSES_KEY, JSON.stringify(list))
}

export default function SubjectManager() {
  const [courses, setCourses] = useState([])
  const [form, setForm] = useState({ code: '', name: '', topics: '' })
  const [editingId, setEditingId] = useState(null)
  const [query, setQuery] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    setCourses(readCourses())
  }, [])

  function showMsg(text) {
    setMsg(text)
    setTimeout(() => setMsg(''), 3000)
  }

  function resetForm() {
    setEditingId(null)
    setForm({ code: '', name: '', topics: '' })
  }

  function validate() {
    if (!form.code.trim()) return 'Course code required'
    if (!form.name.trim()) return 'Course name required'
    return null
  }

  function handleAddOrUpdate() {
    const err = validate()
    if (err) return showMsg(err)
    const current = readCourses()
    if (editingId) {
      const updated = current.map(c => (c.id === editingId ? { ...c, code: form.code.trim(), name: form.name.trim(), topics: form.topics.split(',').map(t => t.trim()).filter(Boolean) } : c))
      saveCourses(updated)
      setCourses(updated)
      showMsg('Course updated')
    } else {
      if (current.some(c => c.code.toLowerCase() === form.code.trim().toLowerCase())) return showMsg('Course code already exists')
      const item = {
        id: 'c_' + Date.now(),
        code: form.code.trim(),
        name: form.name.trim(),
        topics: form.topics.split(',').map(t => t.trim()).filter(Boolean),
        createdAt: new Date().toISOString()
      }
      const updated = [item, ...current]
      saveCourses(updated)
      setCourses(updated)
      showMsg('Course created')
    }
    resetForm()
  }

  function handleEdit(c) {
    setEditingId(c.id)
    setForm({ code: c.code, name: c.name, topics: (c.topics || []).join(', ') })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function handleRemove(id) {
    if (!confirm('Remove this course module?')) return
    const updated = readCourses().filter(c => c.id !== id)
    saveCourses(updated)
    setCourses(updated)
    showMsg('Course removed')
  }

  function filtered() {
    const q = query.trim().toLowerCase()
    if (!q) return courses
    return courses.filter(c =>
      (c.code || '').toLowerCase().includes(q) ||
      (c.name || '').toLowerCase().includes(q) ||
      (c.topics || []).join(' ').toLowerCase().includes(q)
    )
  }

  function exportCSV() {
    const rows = courses.map(c => `${c.code},${c.name},"${(c.topics || []).join(';')}"`)
    const csv = ['Course Code,Course Name,Topics', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'courses.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  function importCSV(text) {
    const lines = text.split('\n').map(s => s.trim()).filter(Boolean)
    const parsed = []
    for (let i = 0; i < lines.length; i++) {
      const cols = lines[i].split(',').map(c => c.trim())
      if (cols.length < 2) continue
      const code = cols[0]
      const name = cols[1]
      const topicsRaw = cols.slice(2).join(',')
      const topics = topicsRaw ? topicsRaw.split(/;|,/).map(t => t.trim()).filter(Boolean) : []
      parsed.push({ id: 'c_imp_' + Date.now() + '_' + i, code, name, topics, createdAt: new Date().toISOString() })
    }
    if (parsed.length === 0) return showMsg('No valid rows found')
    const combined = [...parsed, ...readCourses()]
    saveCourses(combined)
    setCourses(combined)
    showMsg(`Imported ${parsed.length} courses`)
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
      <h3>Create Course Module</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Course Code</label>
        <input value={form.code} onChange={e => setForm({ ...form, code: e.target.value })} placeholder="e.g. IT201" />

        <label>Course Name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g. Web Development" />

        <label>Topics (comma separated)</label>
        <input value={form.topics} onChange={e => setForm({ ...form, topics: e.target.value })} placeholder="HTML, CSS, JS" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAddOrUpdate} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
          {editingId ? 'Update Course' : 'Create Course'}
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
        <input placeholder="Search by code, name, or topic" value={query} onChange={e => setQuery(e.target.value)} style={{ padding: 8, flex: 1 }} />
      </div>

      <div>
        {filtered().length === 0 ? (
          <div style={{ color: '#6b7280' }}>No courses found.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
                <th style={{ padding: 8 }}>Course Code</th>
                <th>Course Name</th>
                <th>Topics</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered().map(c => (
                <tr key={c.id}>
                  <td style={{ padding: 8 }}>{c.code}</td>
                  <td>{c.name}</td>
                  <td>{(c.topics || []).join(', ')}</td>
                  <td>
                    <button onClick={() => handleEdit(c)} style={{ marginRight: 8 }}>Edit</button>
                    <button onClick={() => handleRemove(c.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px', borderRadius: 4 }}>
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
        Course modules are saved locally for now. Replace localStorage calls with API endpoints when you integrate your backend.
      </div>
    </div>
  )
}
