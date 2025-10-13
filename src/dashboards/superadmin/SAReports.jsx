import React, { useEffect, useState } from 'react'

const STUD_KEY = 'app_students_v1'
const ATT_KEY = 'app_attendance_v1'
function read(key) { return JSON.parse(localStorage.getItem(key) || '[]') }

export default function SAReports() {
  const [students, setStudents] = useState([])
  const [attendance, setAttendance] = useState([])
  const [filters, setFilters] = useState({ studentId: '', year: '' })
  const [report, setReport] = useState([])

  useEffect(() => {
    setStudents(read(STUD_KEY))
    setAttendance(read(ATT_KEY))
  }, [])

  function run() {
    let rows = read(ATT_KEY)
    if (filters.studentId) rows = rows.filter(r => r.studentId === filters.studentId)
    if (filters.year) rows = rows.filter(r => (r.academicYear || r.year) === filters.year)
    setReport(rows)
  }

  function exportCSV() {
    const rows = report.map(r => `${r.studentId},${r.courseCode || ''},${r.courseName || ''},${r.markedAt},${r.method || ''}`)
    const csv = ['Student ID,Course,Course Name,Time,Method', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'institute_attendance_report.csv'; a.click(); URL.revokeObjectURL(url)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Institute Reports</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Filter Student ID (optional)</label>
        <input value={filters.studentId} onChange={e => setFilters({ ...filters, studentId: e.target.value })} />
        <label>Academic Year (optional)</label>
        <input value={filters.year} onChange={e => setFilters({ ...filters, year: e.target.value })} placeholder="e.g. 2025/2026" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={run} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Run Report</button>
        <button onClick={exportCSV} style={{ marginLeft: 8, padding: '8px 12px' }}>Export CSV</button>
      </div>

      <hr style={{ margin: '18px 0' }} />

      {report.length === 0 ? <div style={{ color: '#6b7280' }}>No records. Run a report to view results.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
              <th style={{ padding: 8 }}>Student ID</th>
              <th>Course</th>
              <th>Time</th>
              <th>Method</th>
            </tr>
          </thead>
          <tbody>
            {report.map(r => (
              <tr key={r.id}>
                <td style={{ padding: 8 }}>{r.studentId}</td>
                <td>{r.courseCode || ''} — {r.courseName || ''}</td>
                <td>{new Date(r.markedAt).toLocaleString()}</td>
                <td>{r.method || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
