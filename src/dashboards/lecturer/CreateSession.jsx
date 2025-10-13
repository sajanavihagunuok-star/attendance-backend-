import React, { useEffect, useState, useRef } from 'react'
import QRCode from 'qrcode'
import { readSessions, createSession, removeSession } from '../../utils/lecturerSessions'
import { readSubjects, findByCode, searchCodes, seedExample } from '../../utils/subjects'


// This component reads subjects directly from localStorage key "app_subjects_v1"
// to avoid any import/serialization mismatch between admin and lecturer pages.

function fmt(ts) { return ts ? new Date(ts).toLocaleString() : '' }
function secondsToHuman(sec) {
  if (sec <= 0) return '00:00'
  const m = Math.floor(sec / 60)
  const s = sec % 60
  return `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`
}

function readSubjectsFromStorage() {
  try {
    const raw = localStorage.getItem('app_subjects_v1') || '[]'
    const arr = JSON.parse(raw)
    if (!Array.isArray(arr)) return []
    return arr.map(s => ({ code: (s.code||'').toString().trim().toUpperCase(), title: s.title||'', ...s }))
  } catch (e) {
    console.error('readSubjectsFromStorage parse error', e)
    return []
  }
}

export default function CreateSession() {
  const [courseCode, setCourseCode] = useState('')
  const [courseName, setCourseName] = useState('')
  const [dateStr, setDateStr] = useState('')
  const [timeStr, setTimeStr] = useState('')
  const [duration, setDuration] = useState(5)
  const [sessions, setSessions] = useState([])
  const [qrDataUrl, setQrDataUrl] = useState(null)
  const [selectedSession, setSelectedSession] = useState(null)
  const [searchQ, setSearchQ] = useState('')
  const [codeSuggestions, setCodeSuggestions] = useState([])
  const suggestionsRef = useRef(null)
  const subjectsRef = useRef([])

  // load subjects directly from localStorage on mount and whenever storage changes
  useEffect(() => {
    function load() {
      const subs = readSubjectsFromStorage()
      subjectsRef.current = subs
      console.debug('CreateSession loaded subjects', subs)
    }
    load()
    // listen to storage events (other tabs/admin) so lecturer page updates live
    function onStorage(e) {
      if (e.key && e.key !== 'app_subjects_v1') return
      load()
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  useEffect(() => {
    setSessions(readSessions())
    const t = setInterval(() => setSessions(readSessions()), 1000)
    return () => clearInterval(t)
  }, [])

  // When courseCode changes, normalize and try to auto-fill from exact match
  useEffect(() => {
    const normalized = (courseCode || '').toString().trim().toUpperCase()
    if (!normalized) {
      setCodeSuggestions([])
      return
    }

    // exact match priority: search subjectsRef
    const exact = subjectsRef.current.find(s => s.code === normalized)
    if (exact && exact.title) {
      console.debug('Exact subject match for code', normalized, exact)
      setCourseName(exact.title)
      const others = subjectsRef.current.filter(s => s.code.startsWith(normalized) && s.code !== exact.code)
      setCodeSuggestions([exact, ...others].slice(0, 10))
      return
    }

    // otherwise show prefix suggestions from subjectsRef
    const list = subjectsRef.current.filter(s => s.code.startsWith(normalized)).slice(0, 10)
    setCodeSuggestions(list)
  }, [courseCode])

  // When user selects a suggestion, fill both code + title and clear suggestions
  function pickSuggestion(s) {
    setCourseCode(s.code)
    setCourseName(s.title || '')
    setCodeSuggestions([])
    const el = document.querySelector('input[type="date"]')
    if (el) el.focus()
  }

  function validateCreate() {
    if (!courseCode.trim()) return 'Course code required'
    if (!courseName.trim()) return 'Course title required'
    if (!dateStr || !timeStr) return 'Date and time required'
    if (!duration || parseInt(duration, 10) <= 0) return 'Duration must be at least 1 minute'
    const combined = new Date(`${dateStr}T${timeStr}:00`)
    if (isNaN(combined.getTime())) return 'Invalid date or time'
    return null
  }

  async function genQrForSession(session) {
    const payload = JSON.stringify({ id: session.id, code: session.courseCode, pin: session.pin })
    try {
      const url = await QRCode.toDataURL(payload, { margin: 1, width: 600 })
      setQrDataUrl(url)
      setSelectedSession(session)
    } catch (e) {
      console.error('QR error', e)
    }
  }
  function closeQr() { setQrDataUrl(null); setSelectedSession(null) }

  function computeStart() {
    const combined = new Date(`${dateStr}T${timeStr}:00`)
    if (!isNaN(combined.getTime())) return combined.getTime()
    return Date.now()
  }

  function handleCreate(e) {
    e && e.preventDefault()
    const err = validateCreate()
    if (err) return alert(err)
    const start = computeStart()
    const s = createSession({ courseName, courseCode: courseCode.toUpperCase(), startTs: start, durationMinutes: parseInt(duration, 10) })
    setSessions(readSessions())
    genQrForSession(s)
    // clear inputs but keep subjects loaded
    setCourseCode(''); setCourseName(''); setDateStr(''); setTimeStr(''); setDuration(5); setCodeSuggestions([])
  }

  function handleEnd(id) {
    if (!confirm('End session now?')) return
    removeSession(id)
    setSessions(readSessions())
  }

  function timeLabel(s) {
    const now = Date.now()
    if (!s) return ''
    if (s.start > now) {
      const sec = Math.max(0, Math.floor((s.start - now) / 1000))
      return 'Starts in ' + secondsToHuman(sec)
    }
    const sec = Math.max(0, Math.floor((s.end - now) / 1000))
    if (sec === 0) return 'Expired'
    return secondsToHuman(sec)
  }

  // Clicking outside suggestions area should hide them
  useEffect(() => {
    function onDocClick(e) {
      if (suggestionsRef.current && !suggestionsRef.current.contains(e.target)) setCodeSuggestions([])
    }
    document.addEventListener('click', onDocClick)
    return () => document.removeEventListener('click', onDocClick)
  }, [])

  const matched = (searchQ || '').trim() ? readSessions().filter(s => {
    const q = searchQ.trim().toLowerCase()
    return (s.courseCode || '').toLowerCase().includes(q) || (s.courseName || '').toLowerCase().includes(q)
  }) : []

  return (
    <div style={{ display: 'flex', gap: 18 }}>
      <div style={{ flex: 1, minWidth: 420 }}>
        <h3 style={{ marginTop: 0 }}>Create Session</h3>

        <form onSubmit={handleCreate} style={{ display: 'grid', gap: 8 }}>
          <label>Course Code</label>
          <input
            value={courseCode}
            onChange={e => setCourseCode(e.target.value.toUpperCase())}
            placeholder="e.g. IT201"
            autoComplete="off"
          />
          {codeSuggestions.length > 0 && (
            <div ref={suggestionsRef} style={{ border: '1px solid #eee', padding: 6, borderRadius: 6, background: '#fff' }}>
              {codeSuggestions.map(s => (
                <div key={s.code} style={{ padding: 6, cursor: 'pointer' }} onClick={() => pickSuggestion(s)}>
                  <strong>{s.code}</strong> — <span style={{ color: '#6b7280' }}>{s.title}</span>
                </div>
              ))}
            </div>
          )}

          <label>Course Title (auto-filled)</label>
          <input value={courseName} onChange={e => setCourseName(e.target.value)} placeholder="Course title" />

          <div style={{ display: 'flex', gap: 8 }}>
            <div style={{ flex: 1 }}>
              <label>Date</label>
              <input type="date" value={dateStr} onChange={e => setDateStr(e.target.value)} />
            </div>
            <div style={{ width: 140 }}>
              <label>Time</label>
              <input type="time" value={timeStr} onChange={e => setTimeStr(e.target.value)} />
            </div>
          </div>

          <label>Duration (minutes)</label>
          <input type="number" min={1} value={duration} onChange={e => setDuration(e.target.value)} />

          <div style={{ marginTop: 8 }}>
            <button type="submit" style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Generate QR + PIN</button>
            <button type="button" onClick={() => { setCourseCode(''); setCourseName(''); setDateStr(''); setTimeStr(''); setDuration(5); setCodeSuggestions([]) }} style={{ marginLeft: 8, padding: '8px 12px' }}>Clear</button>
          </div>
        </form>

        <hr style={{ margin: '14px 0' }} />

        <div>
          <label>Search active sessions</label>
          <input placeholder="Search code or title" value={searchQ} onChange={e => setSearchQ(e.target.value)} />
        </div>

        {searchQ.trim() !== '' && (
          <>
            <h4 style={{ marginTop: 12 }}>Search results</h4>
            {matched.length === 0 ? <div style={{ color: '#6b7280' }}>No sessions</div> : matched.map(m => (
              <div key={m.id} style={{ border: '1px solid #eee', padding: 8, marginBottom: 8, borderRadius: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 700 }}>{m.courseCode} — {m.courseName}</div>
                  <div style={{ color: '#6b7280' }}>Ends: {fmt(m.end)} | PIN: <strong>{m.pin}</strong></div>
                  <div style={{ color: '#0b79f7', marginTop: 6 }}>{timeLabel(m)}</div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <button onClick={() => genQrForSession(m)} style={{ padding: '6px 8px' }}>Full screen</button>
                  <button onClick={() => { setCourseCode(m.courseCode); setCourseName(m.courseName); window.scrollTo({ top: 0, behavior: 'smooth' }) }} style={{ padding: '6px 8px' }}>Use</button>
                </div>
              </div>
            ))}
          </>
        )}

        <h4 style={{ marginTop: 12 }}>Active sessions</h4>
        {sessions.length === 0 ? <div style={{ color: '#6b7280' }}>No active sessions</div> :
          sessions.map(s => (
            <div key={s.id} style={{ border: '1px solid #eee', padding: 10, marginBottom: 8, borderRadius: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700 }}>{s.courseCode} — {s.courseName}</div>
                <div style={{ color: '#6b7280' }}>{fmt(s.start)} — {fmt(s.end)}</div>
                <div style={{ marginTop: 6 }}>PIN: <strong>{s.pin}</strong></div>
                <div style={{ color: '#0b79f7', marginTop: 6 }}>{timeLabel(s)}</div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <button onClick={() => genQrForSession(s)} style={{ padding: '8px 10px' }}>Full screen</button>
                <button onClick={() => handleEnd(s.id)} style={{ padding: '8px 10px', background: '#ef4444', color: '#fff', border: 'none', borderRadius: 6 }}>End</button>
              </div>
            </div>
          ))
        }
      </div>

      <div style={{ width: 380 }}>
        <h3 style={{ marginTop: 0 }}>Live Preview</h3>
        {sessions[0] ? (
          <div style={{ border: '1px solid #eee', padding: 10, borderRadius: 6 }}>
            <div style={{ fontWeight: 700 }}>{sessions[0].courseCode} — {sessions[0].courseName}</div>
            <div style={{ color: '#6b7280' }}>{fmt(sessions[0].start)} — {fmt(sessions[0].end)}</div>
            <div style={{ marginTop: 8 }}>PIN: <strong>{sessions[0].pin}</strong></div>
            <div style={{ marginTop: 12 }}>
              {qrDataUrl ? <img src={qrDataUrl} alt="QR" style={{ width: '100%', height: 'auto' }} /> : <div style={{ color: '#6b7280' }}>Click Full screen to view QR</div>}
            </div>
          </div>
        ) : <div style={{ color: '#6b7280' }}>No live session</div>}

        <h4 style={{ marginTop: 12 }}>Recent (24h)</h4>
        <div style={{ maxHeight: 300, overflow: 'auto' }}>
          {JSON.parse(localStorage.getItem('lecturer_recent_sessions_v1') || '[]').slice(0, 20).map(r => (
            <div key={r.id} style={{ border: '1px solid #eee', padding: 8, borderRadius: 6, marginBottom: 8 }}>
              <div style={{ fontWeight: 700 }}>{r.courseCode || r.id}</div>
              <div style={{ color: '#6b7280' }}>Ended: {new Date(r.endedAt).toLocaleString()}</div>
              <div>Marked: {r.attendanceCount || 0}</div>
            </div>
          ))}
        </div>
      </div>

      {qrDataUrl && <QRModal url={qrDataUrl} onClose={closeQr} session={selectedSession} />}
    </div>
  )
}

function QRModal({ url, onClose, session }) {
  if (!url) return null
  return (
    <div onClick={onClose} style={{ position: 'fixed', left: 0, top: 0, width: '100vw', height: '100vh', background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000 }}>
      <div onClick={e => e.stopPropagation()} style={{ background: '#fff', padding: 18, borderRadius: 8, textAlign: 'center', maxWidth: '88vw' }}>
        <img src={url} alt="QR" style={{ maxWidth: '80vw', height: 'auto' }} />
        <div style={{ marginTop: 12, fontWeight: 700 }}>{session?.courseCode} — {session?.courseName}</div>
        <div style={{ marginTop: 6 }}>PIN: <strong>{session?.pin}</strong></div>
        <div style={{ marginTop: 12 }}><button onClick={onClose} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Close</button></div>
      </div>
    </div>
  )
}
