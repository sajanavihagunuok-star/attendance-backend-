import React, { useEffect, useState } from 'react'
const STUD_KEY = 'app_students_v1'
const ATT_KEY = 'app_attendance_v1'
function read(key) { return JSON.parse(localStorage.getItem(key) || '[]') }

export default function ReportsGenerator() {
  const [students, setStudents] = useState([])
  const [attendance, setAttendance] = useState([])
  const [districts, setDistricts] = useState([])
  const [filters, setFilters] = useState({ district: '', year: '' })
  const [report, setReport] = useState([])

  useEffect(() => {
    const s = read(STUD_KEY)
    setStudents(s)
    setAttendance(read(ATT_KEY))
    // derive districts dynamically from student registrations; only include districts present
    const ds = Array.from(new Set((s || []).map(x => (x.district || '').trim()).filter(Boolean))).sort()
    setDistricts(ds)
  }, [])

  function generate() {
    let list = students
    if (filters.district) list = list.filter(s => (s.district || '').toLowerCase() === filters.district.toLowerCase())
    if (filters.year) list = list.filter(s => s.year === filters.year)
    const rows = list.map(s => ({
      id: s.id, name: s.name, studentId: s.studentId, year: s.year, batch: s.batch || '-', district: s.district || '-'
    }))
    setReport(rows)
  }

  function exportCSV() {
    const rows = report.map(r => `${r.studentId},${r.name},${r.year},${r.batch},${r.district}`)
    const csv = ['Student ID,Name,Year,Batch,District', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'user_report.csv'; a.click(); URL.revokeObjectURL(url)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Reports Generator</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>District</label>
        <select value={filters.district} onChange={e => setFilters({ ...filters, district: e.target.value })}>
          <option value="">All districts</option>
          {districts.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
        <label>Academic Year</label>
        <input value={filters.year} onChange={e => setFilters({ ...filters, year: e.target.value })} placeholder="e.g. 2025/2026" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={generate} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Generate</button>
        <button onClick={exportCSV} style={{ marginLeft: 8, padding: '8px 12px' }}>Export CSV</button>
      </div>

      <hr style={{ margin: '18px 0' }} />

      {report.length === 0 ? <div style={{ color: '#6b7280' }}>No records. Generate a report to view results.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Student ID</th><th>Name</th><th>Year</th><th>Batch</th><th>District</th>
          </tr></thead>
          <tbody>
            {report.map(r => (
              <tr key={r.id}>
                <td style={{ padding: 8 }}>{r.studentId}</td>
                <td>{r.name}</td>
                <td>{r.year}</td>
                <td>{r.batch}</td>
                <td>{r.district}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ marginTop: 12, color: '#6b7280' }}>
        District list is driven by actual student registrations; districts with no students will not appear.
      </div>
    </div>
  )
}
