import React, { useEffect, useState } from 'react'
import Home from './pages/Home'
import Login from './pages/Login'
import LecturerDashboard from './dashboards/lecturer/LecturerDashboard'
import AdminDashboard from './dashboards/admin/AdminDashboard'
import OwnerDashboard from './dashboards/owner/OwnerDashboard'
import SuperAdminDashboard from './dashboards/superadmin/SuperAdminDashboard'
import Student from './pages/Student'
import MigratePasswords from './pages/MigratePasswords'

const SESSION_KEY = 'app_user_v1'

const getHash = () =>
  typeof window !== 'undefined' && window.location.hash
    ? window.location.hash.replace('#/', '').replace('#', '')
    : ''

function readSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY) || null
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export default function App() {
  const [route, setRoute] = useState(getHash())
  const [user, setUser] = useState(() => readSession())

  useEffect(() => {
    function onHashChange() {
      setRoute(getHash())
      setUser(readSession())
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  useEffect(() => {
    if (!user) return
    if (route === '' || route === 'login' || route === '/') {
      if (user.role === 'owner') window.location.hash = '#/dashboard/owner'
      else if (user.role === 'superadmin') window.location.hash = '#/dashboard/superadmin'
      else if (user.role === 'admin') window.location.hash = '#/dashboard/admin'
      else if (user.role === 'lecturer') window.location.hash = '#/dashboard/lecturer'
      else if (user.role === 'student') window.location.hash = '#/student'
    }
  }, [user, route])

  if (route.startsWith('dashboard/owner')) return <OwnerDashboard />
  if (route.startsWith('dashboard/superadmin')) return <SuperAdminDashboard />
  if (route.startsWith('dashboard/admin')) return <AdminDashboard />
  if (route.startsWith('dashboard/lecturer')) return <LecturerDashboard />
  if (route === 'student') return <Student />
  if (route === 'login') return <Login />
  if (route === 'migrate') return <MigratePasswords />
  return <Home />
}
