import React from 'react'

function formatCountdown(ms) {
  const sec = Math.floor(ms / 1000)
  if (sec <= 0) return 'Expired'
  const min = Math.floor(sec / 60)
  const remSec = sec % 60
  return `${min}m ${remSec}s left`
}

function SessionList({ sessions = [], compact = false, onRefresh }) {
  const now = Date.now()

  return (
    <div>
      {!compact && <h3 style={{ marginTop: 0 }}>Session List</h3>}
      {sessions.length === 0 ? (
        <div className="muted">No sessions yet.</div>
      ) : (
        <ul style={{ listStyle: 'none', paddingLeft: 0 }}>
          {sessions.map((s) => {
            const expired = now > s.expiresAt
            const countdown = formatCountdown(s.expiresAt - now)
            return (
              <li key={s.id} style={{ marginBottom: 12, padding: 10, border: '1px solid #eee', borderRadius: 8 }}>
                <div><strong>{s.courseCode}</strong> — {s.courseName}</div>
                <div>{s.date} {s.time} ({s.duration} min)</div>
                <div>
                  PIN: <strong>{s.pin}</strong>{' '}
                  <span style={{ color: expired ? '#ef4444' : '#10b981' }}>
                    ({countdown})
                  </span>
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

export default SessionList
