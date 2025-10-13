import React, { useState } from 'react'
import AuthGuard from '../../components/AuthGuard'
import SAAdmins from './SAAdmins'
import SALecturers from './SALecturers'
import SAReports from './SAReports'
import SAAcademicYears from './SAAcademicYears'
import SABranding from './SABranding'
import SASubscription from './SASubscription'
import SAAnalytics from './SAAnalytics'
import SAProfile from './SAProfile'
import SATickets from './SATickets'

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

export default function SuperAdminDashboard() {
  const [tab, setTab] = useState('admins')

  return (
    <AuthGuard allowed={['superadmin']}>
      <div style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button onClick={() => window.history.back()} style={{ padding: '6px 10px' }}>Back</button>
            <h2 style={{ margin: 0 }}>Super Admin Console</h2>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div style={{ color: '#374151' }}>Super Admin</div>
            <button
              onClick={() => { localStorage.removeItem('app_user_v1'); window.location.hash = '#/login' }}
              style={{ padding: '6px 10px', background: '#ef4444', color: '#fff', border: 'none', borderRadius: 6 }}
            >
              Logout
            </button>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 12, borderBottom: '1px solid #e5e7eb', marginBottom: 16, flexWrap: 'wrap' }}>
          <TabButton active={tab === 'admins'} onClick={() => setTab('admins')}>Admins</TabButton>
          <TabButton active={tab === 'lecturers'} onClick={() => setTab('lecturers')}>Lecturers</TabButton>
          <TabButton active={tab === 'reports'} onClick={() => setTab('reports')}>Reports</TabButton>
          <TabButton active={tab === 'years'} onClick={() => setTab('years')}>Academic Years</TabButton>
          <TabButton active={tab === 'branding'} onClick={() => setTab('branding')}>Branding</TabButton>
          <TabButton active={tab === 'subscription'} onClick={() => setTab('subscription')}>Subscription</TabButton>
          <TabButton active={tab === 'analytics'} onClick={() => setTab('analytics')}>Analytics</TabButton>
          <TabButton active={tab === 'tickets'} onClick={() => setTab('tickets')}>Tickets</TabButton>
          <TabButton active={tab === 'profile'} onClick={() => setTab('profile')}>Profile</TabButton>
        </div>

        <div style={{ minHeight: 420 }}>
          {tab === 'admins' && <SAAdmins />}
          {tab === 'lecturers' && <SALecturers />}
          {tab === 'reports' && <SAReports />}
          {tab === 'years' && <SAAcademicYears />}
          {tab === 'branding' && <SABranding />}
          {tab === 'subscription' && <SASubscription />}
          {tab === 'analytics' && <SAAnalytics />}
          {tab === 'tickets' && <SATickets />}
          {tab === 'profile' && <SAProfile />}
        </div>
      </div>
    </AuthGuard>
  )
}
