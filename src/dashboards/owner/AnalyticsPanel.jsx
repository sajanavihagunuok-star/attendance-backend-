import React, { useEffect, useState } from 'react'

const STUD_KEY = 'app_students_v1'
const INST_KEY = 'app_institutes_v1'
const ATT_KEY = 'app_attendance_v1'

function read(key) { return JSON.parse(localStorage.getItem(key) || '[]') }

export default function AnalyticsPanel() {
  const [totals, setTotals] = useState({ users: 0, institutes: 0, sessions: 0 })
  const [recent, setRecent] = useState([])

  useEffect(() => {
    const students = read(STUD_KEY)
    const institutes = read(INST_KEY)
    const attendance = read(ATT_KEY)
    setTotals({ users: students.length, institutes: institutes.length, sessions: attendance.length })
    setRecent([{ msg: 'Server code online', ts: new Date().toISOString() }])
  }, [])

  return (
    <div style={{ padding: 12 }}>
      <h3>System Analytics (mock)</h3>

      <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
        <div style={{ padding: 12, border: '1px solid #eee', borderRadius: 6, minWidth: 140 }}>
          <div style={{ fontSize: 20, fontWeight: 'bold' }}>{totals.users}</div>
          <div style={{ color: '#6b7280' }}>Total Users</div>
        </div>
        <div style={{ padding: 12, border: '1px solid #eee', borderRadius: 6, minWidth: 140 }}>
          <div style={{ fontSize: 20, fontWeight: 'bold' }}>{totals.institutes}</div>
          <div style={{ color: '#6b7280' }}>Institutes</div>
        </div>
        <div style={{ padding: 12, border: '1px solid #eee', borderRadius: 6, minWidth: 140 }}>
          <div style={{ fontSize: 20, fontWeight: 'bold' }}>{totals.sessions}</div>
          <div style={{ color: '#6b7280' }}>Sessions</div>
        </div>
      </div>

      <h4>Recent Activity</h4>
      <ul>
        {recent.map((r, i) => <li key={i}>{r.msg} — {new Date(r.ts).toLocaleString()}</li>)}
      </ul>
    </div>
  )
}
