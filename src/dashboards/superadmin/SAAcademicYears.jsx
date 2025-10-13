import React, { useEffect, useState } from 'react'

const KEY = 'app_academic_years_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function SAAcademicYears() {
  const [years, setYears] = useState([])
  const [val, setVal] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => setYears(read()), [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function add() {
    const v = val.trim()
    if (!v) return show('Enter academic year')
    if (years.includes(v)) return show('Already exists')
    const updated = [v, ...years]; save(updated); setYears(updated); setVal(''); show('Year added')
  }

  function remove(y) {
    if (!confirm('Remove year?')) return
    const updated = read().filter(x => x !== y); save(updated); setYears(updated); show('Removed')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Academic Years</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 640 }}>
        <label>Academic Year (YYYY/YYYY)</label>
        <input value={val} onChange={e => setVal(e.target.value)} placeholder="e.g. 2025/2026" />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={add} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff' }}>Save</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      {years.length === 0 ? <div style={{ color: '#6b7280' }}>No academic years.</div> : (
        <ul>{years.map(y => <li key={y} style={{ marginBottom: 6 }}>{y} <button onClick={() => remove(y)} style={{ marginLeft: 8 }}>Remove</button></li>)}</ul>
      )}
    </div>
  )
}
