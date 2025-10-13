import React, { useEffect, useState } from 'react'
import CreateSession from './CreateSession'
import ManualAttendance from './ManualAttendance'
import LecturerReports from './LecturerReports'
import LecturerProfile from './LecturerProfile'
import { pruneExpiredSessions } from '../../utils/lecturerSessions'

function Tab({active, onClick, children}) {
  return (
    <button onClick={onClick} style={{
      padding: '8px 12px', border: 'none', background: 'transparent',
      borderBottom: active ? '3px solid #0b79f7' : '3px solid transparent',
      fontWeight: active ? 700 : 500, cursor: 'pointer'
    }}>{children}</button>
  )
}

export default function LecturerDashboard() {
  const [tab, setTab] = useState('create')
  useEffect(() => {
    pruneExpiredSessions()
    const t = setInterval(() => pruneExpiredSessions(), 5000)
    return () => clearInterval(t)
  }, [])

  return (
    <div style={{ maxWidth: 1024, margin: '18px auto', padding: 18, boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{ margin: 0 }}>Lecturer Console</h2>
        <div>
          <button onClick={() => { localStorage.removeItem('app_user_v1'); sessionStorage.removeItem('app_user_v1'); window.location.hash = '#/login' }} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 12px', borderRadius: 6 }}>Logout</button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, borderBottom: '1px solid #e5e7eb', paddingBottom: 8, marginTop: 12 }}>
        <Tab active={tab === 'create'} onClick={() => setTab('create')}>Create Session</Tab>
        <Tab active={tab === 'manual'} onClick={() => setTab('manual')}>Manual Attendance</Tab>
        <Tab active={tab === 'reports'} onClick={() => setTab('reports')}>Reports</Tab>
        <Tab active={tab === 'profile'} onClick={() => setTab('profile')}>Profile</Tab>
      </div>

      <div style={{ marginTop: 16, background: '#fff', padding: 16, minHeight: 520, borderRadius: 8 }}>
        {tab === 'create' && <CreateSession />}
        {tab === 'manual' && <ManualAttendance />}
        {tab === 'reports' && <LecturerReports />}
        {tab === 'profile' && <LecturerProfile />}
      </div>
    </div>
  )
}
