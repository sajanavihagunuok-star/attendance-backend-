// src/components/AuthGuard.jsx
import React, { useEffect, useState } from 'react'
import { readSessionRaw, readActiveSessionId, onActiveSessionChange, isThisTabActive, clearSession } from '../utils/session'

/*
  AuthGuard props:
  - allowed: array of allowed roles (e.g. ['owner','superadmin'])
  - redirectTo: hash route to redirect if not allowed (default '#/login')
  - children: guarded UI

  Behavior:
  - If no session at all -> redirect to redirectTo
  - If session exists but this tab is not the active session -> redirect to login
  - If role mismatches allowed roles -> redirect to the correct dashboard for that role
  - Listens to storage events (active session changes) and reacts immediately
*/

function redirectByRole(role, fallback = '#/login') {
  switch (role) {
    case 'owner': window.location.hash = '#/dashboard/owner'; break
    case 'superadmin': window.location.hash = '#/dashboard/superadmin'; break
    case 'admin': window.location.hash = '#/dashboard/admin'; break
    case 'lecturer': window.location.hash = '#/dashboard/lecturer'; break
    case 'student': window.location.hash = '#/student'; break
    default: window.location.hash = fallback
  }
}

export default function AuthGuard({ allowed = [], redirectTo = '#/login', children }) {
  const [ok, setOk] = useState(null)

  useEffect(() => {
    function evaluate() {
      const session = readSessionRaw()
      if (!session) {
        window.location.hash = redirectTo
        setOk(false)
        return
      }

      // Active-session enforcement: if this tab isn't active, require re-login
      const activeId = readActiveSessionId()
      if (!activeId) {
        // no active session recorded, treat this tab as active if it has a session; set active id to our session
        // but to avoid accidental overwrite, check and set only when safe
        // for simplicity, if no active id we allow current tab
      } else {
        // If activeId exists but doesn't match our session -> force logout/redirect
        if (!isThisTabActive()) {
          // clear local copies for safety and redirect to login
          clearSession()
          window.location.hash = redirectTo
          setOk(false)
          return
        }
      }

      // Role enforcement
      if (allowed && allowed.length > 0) {
        if (!allowed.includes(session.role)) {
          // send user to their dashboard
          redirectByRole(session.role, redirectTo)
          setOk(false)
          return
        }
      }

      setOk(true)
    }

    evaluate()
    const unsub = onActiveSessionChange(() => evaluate())
    return () => unsub()
  }, [allowed, redirectTo])

  if (ok === null) return null
  if (!ok) return null
  return <>{children}</>
}
