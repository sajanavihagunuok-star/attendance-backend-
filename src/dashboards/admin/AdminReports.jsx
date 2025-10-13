import React, { useEffect, useState } from 'react'

const ATT_KEY = 'app_attendance_v1'
const STUD_KEY = 'app_students_v1'
const COURSES_KEY = 'app_courses_v1'

function read(key) {
  return JSON.parse(localStorage.getItem(key) || '[]')
}

export default function AdminReports() {
  const [data, setData] = useState([])
  const [students, setStudents] = useState([])
  const [courses, setCourses] = useState([])
  const [filters, setFilters] = useState({ studentId: '', batch: '', courseCode: '', dateFrom: '', dateTo: '' })
  const [filtered, setFiltered] = useState([])

  useEffect(() => {
    setData(read(ATT_KEY))
    setStudents(read(STUD_KEY))
    setCourses(read(COURSES_KEY))
  }, [])

  useEffect(() => applyFilters(), [data, filters])

  function applyFilters() {
    let list = [...data]
    if (filters.studentId) list = list.filter(r => r.studentId === filters.studentId)
    if (filters.batch) list = list.filter(r => (r.studentId || '').startsWith(filters.batch))
    if (filters.courseCode) list = list.filter(r => r.courseCode === filters.courseCode)
    if (filters.dateFrom) list = list.filter(r => new Date(r.markedAt) >= new Date(filters.dateFrom))
    if (filters.dateTo) list = list.filter(r => new Date(r.markedAt) <= new Date(filters.dateTo))
    setFiltered(list)
  }

  function exportCSV() {
    const rows = filtered.map(r => `${r.studentId},${r.courseCode},${r.courseName},${r.markedAt},${r.method}`)
    const csv = ['Student ID,Course Code,Course Name,Time,Method', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'admin_attendance_report.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Attendance Reports (Admin)</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 900 }}>
        <label>Student ID</label>
        <input value={filters.studentId} onChange={e => setFilters({ ...filters, studentId: e.target.value })} />

        <label>Batch (prefix)</label>
        <input value={filters.batch} onChange={e => setFilters({ ...filters, batch: e.target.value })} />

        <label>Course Code</label>
        <select value={filters.courseCode} onChange={e => setFilters({ ...filters, courseCode: e.target.value })}>
          <option value="">All courses</option>
          {courses.map(c => <option key={c.id} value={c.code}>{c.code} — {c.name}</option>)}
        </select>

        <label>Date From</label>
        <input type="date" value={filters.dateFrom} onChange={e => setFilters({ ...filters, dateFrom: e.target.value })} />

        <label>Date To</label>
        <input type="date" value={filters.dateTo} onChange={e => setFilters({ ...filters, dateTo: e.target.value })} />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={applyFilters} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
          Apply Filters
        </button>
        <button onClick={exportCSV} style={{ marginLeft: 8, padding: '8px 12px' }}>
          Export CSV
        </button>
      </div>

      <div style={{ marginTop: 18 }}>
        {filtered.length === 0 ? (
          <div style={{ color: '#6b7280' }}>No matching records.</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th>Student ID</th>
                <th>Course</th>
                <th>Time</th>
                <th>Method</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(r => (
                <tr key={r.id}>
                  <td style={{ padding: 8 }}>{r.studentId}</td>
                  <td>{r.courseCode} — {r.courseName}</td>
                  <td>{new Date(r.markedAt).toLocaleString()}</td>
                  <td>{r.method}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
