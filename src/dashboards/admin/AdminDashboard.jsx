import React, { useState } from 'react'
import StudentManager from './StudentManager'
import SubjectManager from './SubjectManager'
import LecturerManager from './LecturerManager'
import AcademicYearManager from './AcademicYearManager'
import AdminProfile from './AdminProfile'
import AdminGeofence from './AdminGeofence'
import AdminReports from './AdminReports'

function TabButton({ active, children, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '8px 12px',
        border: 'none',
        borderBottom: active ? '2px solid #0b79f7' : '2px solid transparent',
        background: 'transparent',
        fontWeight: active ? 'bold' : 'normal',
        cursor: 'pointer'
      }}
    >
      {children}
    </button>
  )
}

export default function AdminDashboard() {
  const [tab, setTab] = useState('students')

  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2>🛠️ Admin Dashboard</h2>
        <div>
          <button
            onClick={() => {
              localStorage.removeItem('app_user_v1')
              window.location.hash = '#/'
            }}
            style={{ padding: '6px 10px', background: '#ef4444', color: '#fff', border: 'none', borderRadius: 6 }}
          >
            Logout
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 12, borderBottom: '1px solid #ddd', marginBottom: 16 }}>
        <TabButton active={tab === 'students'} onClick={() => setTab('students')}>Manage Students</TabButton>
        <TabButton active={tab === 'lecturers'} onClick={() => setTab('lecturers')}>Lecturers</TabButton>
        <TabButton active={tab === 'subjects'} onClick={() => setTab('subjects')}>Create Course Modules</TabButton>
        <TabButton active={tab === 'years'} onClick={() => setTab('years')}>Create Academic Year</TabButton>
        <TabButton active={tab === 'geofence'} onClick={() => setTab('geofence')}>Geofence</TabButton>
        <TabButton active={tab === 'reports'} onClick={() => setTab('reports')}>Attendance Reports</TabButton>
        <TabButton active={tab === 'profile'} onClick={() => setTab('profile')}>Profile</TabButton>
      </div>

      <div style={{ minHeight: 360 }}>
        {tab === 'students' && <StudentManager />}
        {tab === 'lecturers' && <LecturerManager />}
        {tab === 'subjects' && <SubjectManager />}
        {tab === 'years' && <AcademicYearManager />}
        {tab === 'geofence' && <AdminGeofence />}
        {tab === 'reports' && <AdminReports />}
        {tab === 'profile' && <AdminProfile />}
      </div>
    </div>
  )
}
