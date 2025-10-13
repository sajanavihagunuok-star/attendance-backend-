import React, { useEffect, useState } from 'react'
import CreateSession from './CreateSession'
import SessionList from './SessionList'
import ManualAttendance from './ManualAttendance'
import Reports from './Reports'
import Profile from './Profile'
import './Lecturer.css'

function TabButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={`tab-btn ${active ? 'active' : ''}`}
      style={{
        padding: '8px 12px',
        borderRadius: 8,
        border: active ? '2px solid #0b79f7' : '1px solid #e5e7eb',
        background: active ? '#eef6ff' : '#fff',
        cursor: 'pointer',
        fontWeight: 600
      }}
    >
      {children}
    </button>
  )
}

export default function Lecturer() {
  const [tab, setTab] = useState('sessions') // sessions, manual, reports, profile, courses
  const [sessions, setSessions] = useState(() => JSON.parse(localStorage.getItem('app_sessions_v1') || '[]'))
  const [courses, setCourses] = useState(() => JSON.parse(localStorage.getItem('app_courses_v1') || '[]'))
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} }
  })

  useEffect(() => {
    function onStorage() {
      setSessions(JSON.parse(localStorage.getItem('app_sessions_v1') || '[]'))
      setCourses(JSON.parse(localStorage.getItem('app_courses_v1') || '[]'))
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  function refreshData() {
    setSessions(JSON.parse(localStorage.getItem('app_sessions_v1') || '[]'))
    setCourses(JSON.parse(localStorage.getItem('app_courses_v1') || '[]'))
  }

  function handleSessionCreated(session) {
    // session already saved by CreateSession; just refresh local state
    refreshData()
    setTab('sessions')
  }

  function handleLogout() {
    localStorage.removeItem('user')
    window.location.hash = '#/plans'
  }

  return (
    <div className="lecturer-root" style={{ padding: 18, fontFamily: 'Inter, system-ui, Arial', minHeight: '80vh' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22 }}>👨‍🏫 Lecturer Dashboard</h1>
          <div style={{ color: '#6b7280', marginTop: 6 }}>Local demo — ready for backend integration</div>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ textAlign: 'right', marginRight: 8 }}>
            <div style={{ fontSize: 13, color: '#374151', fontWeight: 600 }}>{user?.role || 'Lecturer'}</div>
            <div style={{ fontSize: 12, color: '#6b7280' }}>{user?.email || 'lecturer@example.com'}</div>
          </div>

          <button
            onClick={() => window.history.back()}
            style={{ padding: '8px 12px', borderRadius: 8, background: '#fff', border: '1px solid #ddd', cursor: 'pointer' }}
          >
            ← Back
          </button>

          <button
            onClick={handleLogout}
            style={{ padding: '8px 12px', borderRadius: 8, background: '#ef4444', color: '#fff', border: 'none', cursor: 'pointer' }}
          >
            Logout
          </button>
        </div>
      </header>

      <nav style={{ marginTop: 16, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <TabButton active={tab === 'sessions'} onClick={() => setTab('sessions')}>Sessions</TabButton>
        <TabButton active={tab === 'manual'} onClick={() => setTab('manual')}>Manual Attendance</TabButton>
        <TabButton active={tab === 'reports'} onClick={() => setTab('reports')}>Reports</TabButton>
        <TabButton active={tab === 'profile'} onClick={() => setTab('profile')}>Profile</TabButton>
      </nav>

      <main style={{ marginTop: 18, display: 'grid', gridTemplateColumns: '1fr 360px', gap: 18 }}>
        <section style={{ background: '#fff', padding: 12, borderRadius: 10, boxShadow: '0 4px 18px rgba(15,23,42,0.04)' }}>
          {tab === 'sessions' && (
            <>
              <CreateSession onCreated={handleSessionCreated} />
              <div style={{ height: 12 }} />
              <SessionList sessions={sessions} onRefresh={refreshData} />
            </>
          )}

          {tab === 'manual' && <ManualAttendance onMarked={() => { refreshData() }} />}

          {tab === 'reports' && <Reports />}

          {tab === 'profile' && <Profile onProfileUpdate={() => refreshData()} />}
        </section>

        <aside style={{ background: '#fff', padding: 12, borderRadius: 10, boxShadow: '0 4px 18px rgba(15,23,42,0.04)' }}>
          <h4 style={{ marginTop: 0 }}>Active Sessions</h4>
          <SessionList sessions={sessions} compact onRefresh={refreshData} />
          <div style={{ height: 12 }} />
          <h4>Quick Actions</h4>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <button onClick={() => setTab('sessions')} style={{ padding: '8px 10px', borderRadius: 8, background: '#0b79f7', color: '#fff', border: 'none' }}>New Session</button>
            <button onClick={() => { navigator.clipboard && navigator.clipboard.writeText(window.location.href); alert('Page URL copied') }} style={{ padding: '8px 10px', borderRadius: 8, background: '#10b981', color: '#fff', border: 'none' }}>Copy URL</button>
          </div>
        </aside>
      </main>

      <footer style={{ marginTop: 18, color: '#6b7280', textAlign: 'center' }}>Lecturer Dashboard — Local demo (ready for backend)</footer>
    </div>
  )
}
