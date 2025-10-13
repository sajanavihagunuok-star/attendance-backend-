// src/utils/session.js
// Central session helper with single-active-session enforcement.
// - Stores session object in localStorage (remember=true) or sessionStorage (remember=false).
// - Maintains app_active_session_v1 in localStorage to represent the current active session id.
// - Provides read/persist/clear helpers and a listener for active-session changes.

const SESSION_KEY = 'app_user_v1'
const ACTIVE_KEY = 'app_active_session_v1'

// read session from sessionStorage first (tab-scoped) then localStorage
export function readSessionRaw() {
  try {
    const rawSession = sessionStorage.getItem(SESSION_KEY) || localStorage.getItem(SESSION_KEY) || null
    return rawSession ? JSON.parse(rawSession) : null
  } catch {
    return null
  }
}

// read only the active session id (string) from localStorage
export function readActiveSessionId() {
  try {
    return localStorage.getItem(ACTIVE_KEY) || null
  } catch {
    return null
  }
}

// persist session object and mark it as active (writes active id to localStorage).
// remember=true => store session in localStorage permanently (persist across tabs)
// remember=false => store session in sessionStorage (tab-scoped) but we still write active id to localStorage
export function persistSession(sessionObj, remember = true) {
  const safe = {
    id: sessionObj.id || ('u_' + Date.now()),
    displayName: sessionObj.displayName || sessionObj.name || sessionObj.email,
    email: sessionObj.email,
    role: sessionObj.role || 'student',
    createdAt: new Date().toISOString()
  }

  try {
    // write session to chosen storage
    if (remember) {
      localStorage.setItem(SESSION_KEY, JSON.stringify(safe))
      sessionStorage.removeItem(SESSION_KEY)
    } else {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(safe))
      localStorage.removeItem(SESSION_KEY)
    }

    // set active session id in localStorage so other tabs know which session is "current"
    localStorage.setItem(ACTIVE_KEY, safe.id)

    // also mirror active session object for convenience (optional)
    localStorage.setItem(`${ACTIVE_KEY}_data`, JSON.stringify(safe))

    return safe
  } catch (e) {
    console.error('persistSession error', e)
    return null
  }
}

// clear current session both storages and clear active session id only if it belongs to this tab/session
// If a different tab is active we still clear our local storage copies and do not clear the active id.
export function clearSession() {
  try {
    const my = readSessionRaw()
    // remove session copies
    localStorage.removeItem(SESSION_KEY)
    sessionStorage.removeItem(SESSION_KEY)
    // only clear active id if it matches our session id
    const active = readActiveSessionId()
    if (my && active && my.id === active) {
      localStorage.removeItem(ACTIVE_KEY)
      localStorage.removeItem(`${ACTIVE_KEY}_data`)
    }
  } catch (e) {
    console.error('clearSession error', e)
  }
}

// Returns true if the local tab/session is the active session (match by id)
export function isThisTabActive() {
  const session = readSessionRaw()
  const active = readActiveSessionId()
  if (!session || !active) return false
  return session.id === active
}

// Subscribe to active-session changes: callback receives newActiveId (string or null)
export function onActiveSessionChange(callback) {
  function handler(e) {
    if (e.key === ACTIVE_KEY || e.key === `${ACTIVE_KEY}_data`) {
      callback(e.newValue)
    }
  }
  window.addEventListener('storage', handler)
  return () => window.removeEventListener('storage', handler)
}

// convenience: read active session object (if written to ACTIVE_KEY_data)
export function readActiveSessionData() {
  try {
    const raw = localStorage.getItem(`${ACTIVE_KEY}_data`) || null
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

// Simple role check helper
export function hasRole(allowed = []) {
  const s = readSessionRaw()
  if (!s) return false
  if (!allowed || allowed.length === 0) return true
  return allowed.includes(s.role)
}
