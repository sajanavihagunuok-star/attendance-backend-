import React, { useEffect, useState } from 'react'
import { readSessions, readRecent } from '../../utils/lecturerSessions'

// Small inline SVG chart for present vs absent by a grouping
function SimpleBar({ labels, presentCounts, totalCounts }) {
  if (!labels || !labels.length) return null
  const max = Math.max(...totalCounts, 1)
  return (
    <svg width="100%" height={Math.max(120, labels.length * 28)} style={{ background: '#fff' }}>
      {labels.map((lab, i) => {
        const y = i * 28 + 10
        const total = totalCounts[i] || 0
        const present = presentCounts[i] || 0
        const wTotal = (total / max) * 300
        const wPresent = (present / max) * 300
        return (
          <g key={i}>
            <text x={0} y={y + 12} fontSize={12}>{lab}</text>
            <rect x={150} y={y} width={wTotal} height={12} fill="#eee" />
            <rect x={150} y={y} width={wPresent} height={12} fill="#0b79f7" />
            <text x={460} y={y + 12} fontSize={12}>{present}/{total}</text>
          </g>
        )
      })}
    </svg>
  )
}

export default function LecturerReports() {
  const [sessions, setSessions] = useState([])
  const [recent, setRecent] = useState([])
  const [groupBy, setGroupBy] = useState('session') // session | subject | batch | student
  const [selected, setSelected] = useState(null)
  const [chartData, setChartData] = useState(null)

  useEffect(() => {
    setSessions(readSessions())
    setRecent(readRecent())
  }, [])

  function exportCSVForSession(session) {
    const att = JSON.parse(localStorage.getItem('attendance_' + session.id) || '[]')
    const rows = att.map(r => `${r.studentId},${(r.name||'')},${new Date(r.markedAt).toISOString()},${r.pin}`)
    const csv = ['Student ID,Name,MarkedAt,PIN', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = `${session.courseCode||session.id}_attendance.csv`; a.click(); URL.revokeObjectURL(url)
  }

  // build simple analytics for selected grouping
  function showAnalyticsForSession(session) {
    const att = JSON.parse(localStorage.getItem('attendance_' + session.id) || '[]')
    const present = att.length
    // total enrolled in batch/subject student count tries to read app_students_v1 and count matches
    const students = JSON.parse(localStorage.getItem('app_students_v1') || '[]')
    const total = students.length || 0
    setChartData({ labels: [session.courseCode || session.id], presentCounts: [present], totalCounts: [total] })
  }

  // when user selects "subject" analytics, aggregate by subject for recent sessions
  function buildSubjectAnalytics() {
    const recentSessions = [...recent, ...sessions].slice(0, 200)
    const map = {}
    recentSessions.forEach(s => {
      const key = s.courseCode || 'unknown'
      const att = JSON.parse(localStorage.getItem('attendance_' + s.id) || '[]')
      map[key] = map[key] || { present: 0, total: 0 }
      map[key].present += (att || []).length
      // approximate total by number of unique students who ever attended (not perfect); simpler is to use app_students_v1
    })
    // fallback total from students store
    const students = JSON.parse(localStorage.getItem('app_students_v1') || '[]') || []
    const labels = Object.keys(map)
    const present = labels.map(l => map[l].present)
    const total = labels.map(() => students.length)
    setChartData({ labels, presentCounts: present, totalCounts: total })
  }

  useEffect(() => {
    if (!selected) return
    if (groupBy === 'session') showAnalyticsForSession(selected)
    if (groupBy === 'subject') buildSubjectAnalytics()
  }, [selected, groupBy])

  return (
    <div>
      <h3 style={{ marginTop: 0 }}>Reports</h3>

      <div style={{ display: 'flex', gap: 12 }}>
        <div style={{ flex: 1 }}>
          <h4>Active sessions</h4>
          {sessions.length === 0 ? <div style={{ color: '#6b7280' }}>No active sessions</div> : sessions.map(s => (
            <div key={s.id} style={{ border: '1px solid #eee', padding: 8, marginBottom: 8, borderRadius: 6 }}>
              <div style={{ fontWeight: 700 }}>{s.courseCode} — {s.courseName}</div>
              <div style={{ color: '#6b7280' }}>Ends: {new Date(s.end).toLocaleString()}</div>
              <div style={{ marginTop: 8 }}>
                <button onClick={() => { setSelected(s); setGroupBy('session') }} style={{ padding: '6px 8px', marginRight: 6 }}>Inspect</button>
                <button onClick={() => exportCSVForSession(s)} style={{ padding: '6px 8px' }}>Export CSV</button>
              </div>
            </div>
          ))}
        </div>

        <div style={{ width: 420 }}>
          <h4>Recent sessions (24h)</h4>
          {recent.length === 0 ? <div style={{ color: '#6b7280' }}>No recent sessions</div> : recent.map(r => (
            <div key={r.id} style={{ border: '1px solid #eee', padding: 8, marginBottom: 8, borderRadius: 6 }}>
              <div style={{ fontWeight: 700 }}>{r.courseCode || r.id}</div>
              <div style={{ color: '#6b7280' }}>Ended: {new Date(r.endedAt).toLocaleString()}</div>
              <div>Marked: {r.attendanceCount || 0}</div>
            </div>
          ))}
        </div>
      </div>

      <hr style={{ margin: '12px 0' }} />

      <div style={{ display: 'flex', gap: 12 }}>
        <div>
          <label>Group by</label>
          <select value={groupBy} onChange={e => setGroupBy(e.target.value)}>
            <option value="session">Session</option>
            <option value="subject">Subject</option>
          </select>
        </div>

        <div>
          <label>Choose session (for session-wise)</label>
          <select onChange={e => setSelected(JSON.parse(e.target.value || 'null'))}>
            <option value=''>-- choose session --</option>
            {sessions.map(s => <option key={s.id} value={JSON.stringify(s)}>{s.courseCode} — {s.courseName}</option>)}
          </select>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <h4>Chart</h4>
        {chartData ? <SimpleBar labels={chartData.labels} presentCounts={chartData.presentCounts} totalCounts={chartData.totalCounts} /> : <div style={{ color: '#6b7280' }}>Select session or subject to view analytics</div>}
      </div>

      <div style={{ marginTop: 12 }}>
        <h4>Exports</h4>
        <div style={{ color: '#6b7280' }}>Use Export CSV on sessions above for raw CSV. For student-wise or batch-wise exports we can add a selector; tell me which specific CSV columns you need and I'll add it.</div>
      </div>
    </div>
  )
}
