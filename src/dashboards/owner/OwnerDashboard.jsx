import React, { useState } from 'react'
import AuthGuard from '../../components/AuthGuard'
import InstitutesManager from './InstitutesManager'
import PlansManager from './PlansManager'
import PaymentsManager from './PaymentsManager'
import SuperAdminManager from './SuperAdminManager'
import AnalyticsPanel from './AnalyticsPanel'
import SupportCenter from './SupportCenter'
import OwnerProfile from './OwnerProfile'
import CoOwnersManager from './CoOwnersManager'
import AdsManager from './AdsManager'
import ReportsGenerator from './ReportsGenerator'

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

export default function OwnerDashboard() {
  const [tab, setTab] = useState('institutes')

  return (
    <AuthGuard allowed={['owner']}>
      <div style={{ padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button onClick={() => window.history.back()} style={{ padding: '6px 10px' }}>Back</button>
            <h2 style={{ margin: 0 }}>Owner Console</h2>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <div style={{ color: '#374151' }}>Owner</div>
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

        <div style={{ display: 'flex', gap: 12, borderBottom: '1px solid #e5e7eb', marginBottom: 16, flexWrap: 'wrap' }}>
          <TabButton active={tab === 'institutes'} onClick={() => setTab('institutes')}>Institutes</TabButton>
          <TabButton active={tab === 'plans'} onClick={() => setTab('plans')}>Plans</TabButton>
          <TabButton active={tab === 'payments'} onClick={() => setTab('payments')}>Payments</TabButton>
          <TabButton active={tab === 'superadmins'} onClick={() => setTab('superadmins')}>Super Admins</TabButton>
          <TabButton active={tab === 'analytics'} onClick={() => setTab('analytics')}>Analytics</TabButton>
          <TabButton active={tab === 'support'} onClick={() => setTab('support')}>Support</TabButton>
          <TabButton active={tab === 'ads'} onClick={() => setTab('ads')}>Ads</TabButton>
          <TabButton active={tab === 'reports'} onClick={() => setTab('reports')}>Reports</TabButton>
          <TabButton active={tab === 'coowners'} onClick={() => setTab('coowners')}>Co Owners</TabButton>
          <TabButton active={tab === 'profile'} onClick={() => setTab('profile')}>Profile</TabButton>
        </div>

        <div style={{ minHeight: 420 }}>
          {tab === 'institutes' && <InstitutesManager />}
          {tab === 'plans' && <PlansManager />}
          {tab === 'payments' && <PaymentsManager />}
          {tab === 'superadmins' && <SuperAdminManager />}
          {tab === 'analytics' && <AnalyticsPanel />}
          {tab === 'support' && <SupportCenter />}
          {tab === 'ads' && <AdsManager />}
          {tab === 'reports' && <ReportsGenerator />}
          {tab === 'coowners' && <CoOwnersManager />}
          {tab === 'profile' && <OwnerProfile />}
        </div>
      </div>
    </AuthGuard>
  )
}
