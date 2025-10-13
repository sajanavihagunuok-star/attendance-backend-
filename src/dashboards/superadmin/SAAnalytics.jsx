import React, { useEffect, useState } from 'react'

const STUD_KEY = 'app_students_v1'
const LEC_KEY = 'app_lecturers_v1'
const ATT_KEY = 'app_attendance_v1'
function read(key) { return JSON.parse(localStorage.getItem(key) || '[]') }

export default function SAAnalytics() {
  const [totals, setTotals] = useState({ users: 0, lecturers: 0, sessions: 0 })
  const [recent, setRecent] = useState([])

  useEffect(() => {
    const s = read(STUD_KEY); const l = read(LEC_KEY); const a = read(ATT_KEY)
    setTotals({ users: s.length, lecturers: l.length, sessions: a.length })
    setRecent([{ msg: 'Institute data loaded', ts: new Date().toISOString() }])
  }, [])

  return (
    <div style={{ padding: 12 }}>
      <h3>Institute Analytics (mock)</h3>

      <div style={{ display: 'flex', gap: 12, marginBottom: 12 }}>
        <div style={{ padding: 12, border: '1px solid #eee', borderRadius: 6, minWidth: 140 }}>
          <div style={{ fontSize: 20, fontWeight: 'bold' }}>{totals.users}</div>
          <div style={{ color: '#6b7280' }}>Users</div>
        </div>
        <div style={{ padding: 12, border: '1px solid #eee', borderRadius: 6, minWidth: 140 }}>
          <div style={{ fontSize: 20, fontWeight: 'bold' }}>{totals.lecturers}</div>
          <div style={{ color: '#6b7280' }}>Lecturers</div>
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
