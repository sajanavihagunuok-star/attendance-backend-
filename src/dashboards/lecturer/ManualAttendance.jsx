import React, { useEffect, useState } from 'react'
import { readSessions, readAttendance, addAttendance, removeSession } from '../../utils/lecturerSessions'

// Keep selected session per tab (sessionStorage), attendance persisted in localStorage until session ends
const SELECTED_KEY = 'lecturer_selected_session_tab_v1' // per-tab key in sessionStorage

function now() { return Date.now() }
function fmt(ts) { return new Date(ts).toLocaleString() }

export default function ManualAttendance() {
  const [sessions, setSessions] = useState([])
  const [selectedId, setSelectedId] = useState(() => sessionStorage.getItem(SELECTED_KEY) || '')
  const [studentId, setStudentId] = useState('')
  const [pin, setPin] = useState('')
  const [marked, setMarked] = useState([])
  const [msg, setMsg] = useState('')

  useEffect(() => {
    setSessions(readSessions())
    const t = setInterval(() => {
      setSessions(readSessions())
      // refresh marked list if selected
      if (selectedId) setMarked(readAttendance(selectedId))
    }, 1000)
    return () => clearInterval(t)
  }, [selectedId])

  useEffect(() => {
    // when user selects session, store selection per-tab
    if (selectedId) sessionStorage.setItem(SELECTED_KEY, selectedId)
    else sessionStorage.removeItem(SELECTED_KEY)
    setMarked(selectedId ? readAttendance(selectedId) : [])
  }, [selectedId])

  function show(m) { setMsg(m); setTimeout(() => setMsg(''), 3500) }

  function validateStudent(id) {
    try {
      const studs = JSON.parse(localStorage.getItem('app_students_v1') || '[]') || []
      return studs.find(s => (s.studentId || '').toString().toLowerCase() === (id || '').toString().toLowerCase())
    } catch { return null }
  }

  function handleMark() {
    if (!selectedId) return show('Select session first')
    if (!studentId.trim()) return show('Student ID required')
    if (!pin.trim()) return show('PIN required')
    const s = sessions.find(x => x.id === selectedId)
    if (!s) return show('Session not found')
    if (s.pin !== pin.trim()) return show('Incorrect PIN')
    const student = validateStudent(studentId.trim())
    if (!student) return show('Unknown student ID')
    const existing = readAttendance(selectedId).find(r => (r.studentId || '').toLowerCase() === studentId.trim().toLowerCase())
    if (existing) return show('Student already marked')
    const rec = { studentId: studentId.trim(), name: student.name || '', markedAt: Date.now(), pin: pin.trim() }
    addAttendance(selectedId, rec)
    setMarked(readAttendance(selectedId))
    show('Attendance marked')
  }

  function handleEnd() {
    if (!selectedId) return
    if (!confirm('End this session now?')) return
    removeSession(selectedId)
    setSelectedId('')
    setMarked([])
    setSessions(readSessions())
    show('Session ended')
  }

  function openFullScreenFor(id) {
    const s = sessions.find(x => x.id === id)
    if (!s) return
    window.dispatchEvent(new CustomEvent('openSessionQR', { detail: { id: s.id, courseCode: s.courseCode, pin: s.pin } }))
  }

  return (
    <div style={{ display: 'flex', gap: 18 }}>
      <div style={{ flex: 1 }}>
        <h3 style={{ marginTop: 0 }}>Manual Attendance</h3>

        <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '240px 1fr', maxWidth: 800 }}>
          <label>Select active session</label>
          <select value={selectedId} onChange={e => setSelectedId(e.target.value)}>
            <option value=''>-- choose --</option>
            {sessions.map(s => <option key={s.id} value={s.id}>{s.courseCode} — {s.courseName} ({Math.max(0, Math.floor((s.end - now()) / 1000))}s left)</option>)}
          </select>

          <label>Student ID</label>
          <input value={studentId} onChange={e => setStudentId(e.target.value)} placeholder="e.g. ST245" />

          <label>PIN</label>
          <input value={pin} onChange={e => setPin(e.target.value)} placeholder="session PIN" />

          <div></div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={handleMark} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Mark Attendance</button>
            <button onClick={() => { setStudentId(''); setPin('') }} style={{ padding: '8px 12px' }}>Clear</button>
            <button onClick={handleEnd} style={{ padding: '8px 12px', background: '#ef4444', color: '#fff', border: 'none', borderRadius: 6 }}>End Session</button>
          </div>
        </div>

        {msg && <div style={{ marginTop: 12, color: '#0b79f7' }}>{msg}</div>}

        <hr style={{ margin: '12px 0' }} />

        <h4>Marked Students (this session)</h4>
        {marked.length === 0 ? <div style={{ color: '#6b7280' }}>No students marked yet.</div> : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
                <th style={{ padding: 8 }}>Student ID</th>
                <th>Name</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {marked.map((m, i) => (
                <tr key={i}>
                  <td style={{ padding: 8 }}>{m.studentId}</td>
                  <td>{m.name || '-'}</td>
                  <td>{new Date(m.markedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div style={{ width: 360 }}>
        <h3 style={{ marginTop: 0 }}>Session quick info</h3>
        {selectedId ? (() => {
          const s = sessions.find(x => x.id === selectedId)
          if (!s) return <div style={{ color: '#6b7280' }}>Session not found</div>
          const remaining = Math.max(0, Math.floor((s.end - now()) / 1000))
          return (
            <div style={{ border: '1px solid #eee', padding: 10, borderRadius: 6 }}>
              <div style={{ fontWeight: 700 }}>{s.courseCode} — {s.courseName}</div>
              <div>PIN: <strong>{s.pin}</strong></div>
              <div style={{ marginTop: 8 }}>Remaining: {remaining <= 0 ? 'Expired' : `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')}`}</div>
              <div style={{ marginTop: 12 }}>
                <button onClick={() => openFullScreenFor(s.id)} style={{ padding: '8px 12px' }}>Open full screen QR</button>
              </div>
            </div>
          )
        })() : <div style={{ color: '#6b7280' }}>No session selected</div>}

        <h4 style={{ marginTop: 12 }}>Active sessions</h4>
        <div style={{ maxHeight: 360, overflow: 'auto' }}>
          {sessions.length === 0 ? <div style={{ color: '#6b7280' }}>No active sessions</div> : sessions.map(s => (
            <div key={s.id} style={{ border: '1px solid #eee', padding: 8, borderRadius: 6, marginBottom: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <div>{s.courseCode} — {s.courseName}</div>
                <div>{Math.max(0, Math.floor((s.end - now()) / 1000))}s</div>
              </div>
              <div style={{ marginTop: 6 }}>
                <button style={{ padding: '6px 8px', marginRight: 6 }} onClick={() => setSelectedId(s.id)}>Select</button>
                <button style={{ padding: '6px 8px' }} onClick={() => openFullScreenFor(s.id)}>Full screen</button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
