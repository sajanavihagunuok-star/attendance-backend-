import React, { useEffect, useState } from 'react'

const STUDENTS_KEY = 'app_students_v1'
const YEARS_KEY = 'app_academic_years_v1'

function readStudents() {
  return JSON.parse(localStorage.getItem(STUDENTS_KEY) || '[]')
}
function saveStudents(list) {
  localStorage.setItem(STUDENTS_KEY, JSON.stringify(list))
}
function readYears() {
  return JSON.parse(localStorage.getItem(YEARS_KEY) || '[]')
}

export default function StudentManager() {
  const [students, setStudents] = useState([])
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ name: '', studentId: '', year: '', batch: '', program: '' })
  const [query, setQuery] = useState('')
  const [filterYear, setFilterYear] = useState('')
  const [filterBatch, setFilterBatch] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    setStudents(readStudents())
  }, [])

  function resetForm() {
    setEditing(null)
    setForm({ name: '', studentId: '', year: '', batch: '', program: '' })
  }

  function validateForm() {
    if (!form.name.trim()) return 'Name required'
    if (!form.studentId.trim()) return 'Student ID required'
    if (!form.year.trim()) return 'Academic year required'
    return null
  }

  function handleAddOrUpdate() {
    const err = validateForm()
    if (err) {
      showMsg(err, true)
      return
    }
    const list = readStudents()
    if (editing) {
      const updated = list.map(s => (s.id === editing ? { ...s, ...form } : s))
      saveStudents(updated)
      setStudents(updated)
      showMsg('Student updated')
    } else {
      if (list.some(s => s.studentId === form.studentId)) {
        showMsg('Student ID already exists', true)
        return
      }
      const newStudent = { id: 'st_' + Date.now(), ...form, createdAt: new Date().toISOString() }
      const updated = [newStudent, ...list]
      saveStudents(updated)
      setStudents(updated)
      showMsg('Student added')
    }
    resetForm()
  }

  function handleEdit(s) {
    setEditing(s.id)
    setForm({
      name: s.name,
      studentId: s.studentId,
      year: s.year,
      batch: s.batch || '',
      program: s.program || ''
    })
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function handleRemove(id) {
    if (!confirm('Remove this student?')) return
    const updated = readStudents().filter(s => s.id !== id)
    saveStudents(updated)
    setStudents(updated)
    showMsg('Student removed')
  }

  function showMsg(text, isError = false) {
    setMsg(text)
    setTimeout(() => setMsg(''), 3000)
  }

  function filteredList() {
    let list = [...students]
    if (query) {
      const q = query.toLowerCase()
      list = list.filter(s =>
        (s.name || '').toLowerCase().includes(q) ||
        (s.studentId || '').toLowerCase().includes(q) ||
        (s.program || '').toLowerCase().includes(q)
      )
    }
    if (filterYear) list = list.filter(s => s.year === filterYear)
    if (filterBatch) list = list.filter(s => (s.batch || '') === filterBatch)
    return list
  }

  function exportCSV() {
    const rows = students.map(s => `${s.studentId},${s.name},${s.year},${s.batch || ''},${s.program || ''}`)
    const csv = ['Student ID,Name,Year,Batch,Program', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'students.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  function importCSV(text) {
    const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
    const parsed = []
    for (let i = 0; i < lines.length; i++) {
      const cols = lines[i].split(',').map(c => c.trim())
      if (cols.length < 3) continue
      const [studentId, name, year, batch = '', program = ''] = cols
      parsed.push({ id: 'st_' + Date.now() + '_' + i, studentId, name, year, batch, program, createdAt: new Date().toISOString() })
    }
    if (parsed.length === 0) return showMsg('No valid rows found', true)
    const combined = [...parsed, ...readStudents()]
    saveStudents(combined)
    setStudents(combined)
    showMsg(`Imported ${parsed.length} students`)
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

  const years = readYears()

  return (
    <div style={{ padding: 12 }}>
      <h3>Manage Student Database</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Full name" />

        <label>Student ID</label>
        <input value={form.studentId} onChange={e => setForm({ ...form, studentId: e.target.value })} placeholder="Unique ID e.g. S12345" />

        <label>Academic Year</label>
        <select value={form.year} onChange={e => setForm({ ...form, year: e.target.value })}>
          <option value="">Select year</option>
          {years.map(y => <option key={y} value={y}>{y}</option>)}
        </select>

        <label>Program / Subject Year</label>
        <input value={form.program} onChange={e => setForm({ ...form, program: e.target.value })} placeholder="e.g. EIT - 2024" />

        <label>Batch (optional)</label>
        <input value={form.batch} onChange={e => setForm({ ...form, batch: e.target.value })} placeholder="e.g. B1 / S22 prefix" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAddOrUpdate} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
          {editing ? 'Update Student' : 'Add Student'}
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
        <input placeholder="Search by name, id or program" value={query} onChange={e => setQuery(e.target.value)} style={{ padding: 8, flex: 1 }} />
        <select value={filterYear} onChange={e => setFilterYear(e.target.value)} style={{ padding: 8 }}>
          <option value="">All years</option>
          {years.map(y => <option key={y} value={y}>{y}</option>)}
        </select>
        <input placeholder="Batch filter" value={filterBatch} onChange={e => setFilterBatch(e.target.value)} style={{ padding: 8 }} />
      </div>

      <div>
        {filteredList().length === 0 ? (
          <div className="muted">No students found.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
                <th style={{ padding: 8 }}>Name</th>
                <th>Student ID</th>
                <th>Year</th>
                <th>Batch</th>
                <th>Program</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredList().map(s => (
                <tr key={s.id}>
                  <td style={{ padding: 8 }}>{s.name}</td>
                  <td>{s.studentId}</td>
                  <td>{s.year}</td>
                  <td>{s.batch || '-'}</td>
                  <td>{s.program || '-'}</td>
                  <td>
                    <button onClick={() => handleEdit(s)} style={{ marginRight: 8 }}>Edit</button>
                    <button onClick={() => handleRemove(s.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>Remove</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div style={{ marginTop: 12, fontSize: 13, color: '#6b7280' }}>
        Student data is stored locally for now. This component is backend-ready: replace localStorage calls with your API calls when ready.
      </div>
    </div>
  )
}
