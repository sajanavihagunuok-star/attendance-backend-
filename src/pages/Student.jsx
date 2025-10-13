import React, { useState, useEffect } from 'react'

const SESSIONS_KEY = 'app_sessions_v1'
const ATTENDANCE_KEY = 'app_attendance_v1'

function getActiveSessions() {
  const now = Date.now()
  const all = JSON.parse(localStorage.getItem(SESSIONS_KEY) || '[]')
  return all.filter(s => now <= s.expiresAt)
}

function Student() {
  const [studentId, setStudentId] = useState('')
  const [pin, setPin] = useState('')
  const [note, setNote] = useState('')
  const [sessions, setSessions] = useState([])

  useEffect(() => {
    setSessions(getActiveSessions())
  }, [])

  function handleSubmit() {
    if (!studentId || !pin) {
      setNote('Student ID and PIN are required')
      setTimeout(() => setNote(''), 2500)
      return
    }

    const match = sessions.find(s => s.pin === pin)
    if (!match) {
      setNote('Invalid or expired PIN')
      setTimeout(() => setNote(''), 2500)
      return
    }

    const record = {
      id: 'a_' + Date.now(),
      studentId,
      pin,
      courseCode: match.courseCode,
      courseName: match.courseName,
      markedAt: new Date().toISOString(),
      method: 'student'
    }

    const store = JSON.parse(localStorage.getItem(ATTENDANCE_KEY) || '[]')
    localStorage.setItem(ATTENDANCE_KEY, JSON.stringify([record, ...store]))

    setNote('Attendance marked successfully')
    setStudentId('')
    setPin('')
    setTimeout(() => setNote(''), 3000)
  }

  return (
    <div style={{ padding: 24, fontFamily: 'Inter, system-ui' }}>
      <h2>📲 Student Attendance</h2>
      <p style={{ color: '#6b7280' }}>Enter your Student ID and the PIN provided by your lecturer.</p>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 500 }}>
        <label>Student ID</label>
        <input value={studentId} onChange={(e) => setStudentId(e.target.value)} placeholder="e.g. S12345" />

        <label>Session PIN</label>
        <input value={pin} onChange={(e) => setPin(e.target.value)} placeholder="6-digit PIN" />
      </div>

      {note && <div style={{ marginTop: 12, color: '#10b981' }}>{note}</div>}

      <div style={{ marginTop: 16 }}>
        <button
          onClick={handleSubmit}
          style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}
        >
          Mark Attendance
        </button>
      </div>

      <div style={{ marginTop: 24, fontSize: 13, color: '#6b7280' }}>
        Only active sessions are accepted. PINs expire after the session duration.
      </div>
    </div>
  )
}

export default Student
