import React, { useEffect, useState } from 'react'
import './Home.css'

function PlansPage() {
  return (
    <div className="page-content">
      <h2 className="page-heading">Plans</h2>
      <p className="muted">This is the default landing page. Show product plans, pricing, or quick actions here.</p>

      <div className="plans" style={{ marginTop: 12 }}>
        <div className="plan">
          <strong>Free</strong>
          <div className="muted" style={{ marginTop: 8 }}>Basic attendance features for testing</div>
        </div>
        <div className="plan">
          <strong>Pro</strong>
          <div className="muted" style={{ marginTop: 8 }}>Extra analytics and multi-class support</div>
        </div>
      </div>
    </div>
  )
}

function MarkAttendancePage() {
  const [method, setMethod] = useState('pin')
  const [studentId, setStudentId] = useState('')
  const [pinValue, setPinValue] = useState('')
  const [note, setNote] = useState('')

  function handleMark() {
    if (!studentId || !pinValue) {
      setNote('Student ID and PIN are required')
      setTimeout(() => setNote(''), 3000)
      return
    }
    const store = JSON.parse(localStorage.getItem('attendance_records') || '{"attendance":[]}')
    store.attendance.push({ time: new Date().toISOString(), method: 'pin', studentId, pin: pinValue })
    localStorage.setItem('attendance_records', JSON.stringify(store))
    setNote('Attendance recorded (PIN)')
    setStudentId('')
    setPinValue('')
    setTimeout(() => setNote(''), 3000)
  }

  return (
    <div className="page-content">
      <h2 className="page-heading">Mark Attendance</h2>
      <p className="muted">Choose method below or ask your lecturer for the PIN.</p>

      <div className="methods" role="tablist" aria-label="methods" style={{ marginTop: 12 }}>
        <button className={`method ${method === 'scan' ? 'active' : ''}`} onClick={() => setMethod('scan')}>Scan QR</button>
        <button className={`method ${method === 'pin' ? 'active' : ''}`} onClick={() => setMethod('pin')}>Enter PIN</button>
      </div>

      {method === 'scan' ? (
        <div id="scan-area" style={{ marginTop: 14 }}>
          <div className="note">QR scanning placeholder. Implement camera scanning separately.</div>
        </div>
      ) : (
        <div id="pin-area" style={{ marginTop: 14 }}>
          <label htmlFor="student-id">Student ID</label>
          <input id="student-id" type="text" value={studentId} onChange={(e) => setStudentId(e.target.value)} placeholder="e.g. S12345" />

          <label htmlFor="pin-value" style={{ marginTop: 8 }}>PIN</label>
          <input id="pin-value" type="text" value={pinValue} onChange={(e) => setPinValue(e.target.value)} inputMode="numeric" maxLength="12" placeholder="6-digit PIN" />

          <div className="controls">
            <button className="btn primary" onClick={handleMark}>Mark Attendance</button>
            <button className="btn ghost" onClick={() => { setStudentId(''); setPinValue(''); setNote('') }}>Clear</button>
            <div style={{ flex: 1 }}></div>
          </div>

          {note && <div className="note" aria-live="polite" style={{ marginTop: 8 }}>{note}</div>}
        </div>
      )}
    </div>
  )
}

function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [msg, setMsg] = useState('')

  function handleLogin(e) {
    e.preventDefault()
    if (!email || !password) {
      setMsg('Email and password required')
      setTimeout(() => setMsg(''), 3000)
      return
    }
    // Simulate login: save user role and email to localStorage
    const user = { email, role: 'lecturer', loggedAt: new Date().toISOString() }
    localStorage.setItem('user', JSON.stringify(user))
    // Navigate to lecturer dashboard
    window.location.hash = '#/dashboard/lecturer'
  }

  return (
    <div className="page-content">
      <h2 className="page-heading">Login</h2>
      <form onSubmit={handleLogin} className="login-form">
        <label htmlFor="login-email">Email</label>
        <input id="login-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />

        <label htmlFor="login-pass" style={{ marginTop: 8 }}>Password</label>
        <input id="login-pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />

        <div className="controls" style={{ marginTop: 12 }}>
          <button className="btn primary" type="submit">Login</button>
          <button className="btn ghost" type="button" onClick={() => { setEmail(''); setPassword(''); setMsg('') }}>Clear</button>
        </div>

        {msg && <div className="note" style={{ marginTop: 8 }}>{msg}</div>}
      </form>
    </div>
  )
}

export default function Home() {
  // valid values: plans, mark, login
  const [page, setPage] = useState('plans')

  useEffect(() => {
    // initialize from hash
    const h = window.location.hash.replace('#/', '').replace('#', '')
    if (h === 'mark' || h === 'login' || h === 'plans') setPage(h)
    else {
      setPage('plans')
      window.location.hash = '#/plans'
    }

    // listen for back/forward or manual hash change
    function onHash() {
      const newH = window.location.hash.replace('#/', '').replace('#', '')
      if (newH === 'mark' || newH === 'login' || newH === 'plans') setPage(newH)
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  function navigateTo(key) {
    setPage(key)
    window.location.hash = `#/${key}`
  }

  return (
    <div className="wrap">
      <header className="home-header">
        <div className="left-title">
          <div className="big-title">Attendance System</div>
          <div className="big-sub">Mark attendance quickly and securely</div>
        </div>

        <nav className="right-tabs" role="tablist" aria-label="Main navigation">
          <button className={`tab ${page === 'plans' ? 'active-tab' : ''}`} onClick={() => navigateTo('plans')}>Plans</button>
          <button className={`tab ${page === 'mark' ? 'active-tab' : ''}`} onClick={() => navigateTo('mark')}>Mark Attendance</button>
          <button className={`tab ${page === 'login' ? 'active-tab' : ''}`} onClick={() => navigateTo('login')}>Login</button>
        </nav>
      </header>

      <main className="home-main">
        <section className="left-panel">
          {page === 'plans' && <PlansPage />}
          {page === 'mark' && <MarkAttendancePage />}
          {page === 'login' && <LoginPage />}
        </section>

        <aside className="right-panel" aria-hidden="true">
          <div className="panel">
            <h3>Quick Info</h3>
            <p className="muted">Demo storage uses localStorage. Attendance entries persist in your browser for testing.</p>
            <div style={{ marginTop: 12 }}>
              <button className="btn ghost" onClick={() => {
                const store = JSON.parse(localStorage.getItem('attendance_records') || '{"attendance":[]}')
                alert(`Records: ${store.attendance.length}`)
              }}>Show Records Count</button>
            </div>
          </div>
        </aside>
      </main>

      <footer className="footer">Demo — local testing only</footer>
    </div>
  )
}
