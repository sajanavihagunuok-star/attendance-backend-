import React, { useEffect, useState } from 'react'

const YEARS_KEY = 'app_academic_years_v1'

function readYears() {
  return JSON.parse(localStorage.getItem(YEARS_KEY) || '[]')
}
function saveYears(list) {
  localStorage.setItem(YEARS_KEY, JSON.stringify(list))
}

export default function AcademicYearManager() {
  const [years, setYears] = useState([])
  const [value, setValue] = useState('')
  const [msg, setMsg] = useState('')

  useEffect(() => {
    setYears(readYears())
  }, [])

  function showMsg(text) {
    setMsg(text)
    setTimeout(() => setMsg(''), 3000)
  }

  function sanitize(input) {
    return (input || '').trim()
  }

  function validateFormat(v) {
    const parts = v.split('/')
    if (parts.length !== 2) return false
    const a = parseInt(parts[0], 10)
    const b = parseInt(parts[1], 10)
    if (Number.isNaN(a) || Number.isNaN(b)) return false
    if (b !== a + 1) return false
    if (a < 2000 || a > 2100) return false
    return true
  }

  function handleCreate() {
    const v = sanitize(value)
    if (!v) return showMsg('Enter academic year')
    if (!validateFormat(v)) return showMsg('Use format YYYY/YYYY (consecutive years)')
    if (years.includes(v)) return showMsg('Year already exists')
    const updated = [v, ...years].sort((x, y) => (y.localeCompare(x)))
    saveYears(updated)
    setYears(updated)
    setValue('')
    showMsg('Academic year created')
  }

  function handleRemove(y) {
    if (!confirm(`Remove academic year ${y}? This will not delete students automatically.`)) return
    const updated = years.filter(x => x !== y)
    saveYears(updated)
    setYears(updated)
    showMsg('Academic year removed')
  }

  function remainingYears(y) {
    const start = parseInt(y.split('/')[0], 10)
    if (Number.isNaN(start)) return '-'
    const diff = start + 6 - new Date().getFullYear()
    return diff > 0 ? `${diff} year${diff === 1 ? '' : 's'}` : 'expired'
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Create Academic Year</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 640 }}>
        <label>Academic Year Format: YYYY/YYYY</label>
        <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. 2025/2026" />

        <div style={{ gridColumn: '1 / -1', marginTop: 6 }}>
          <button onClick={handleCreate} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
            Create Year
          </button>
          <button onClick={() => { setValue('') }} style={{ marginLeft: 8, padding: '8px 12px' }}>
            Clear
          </button>
          {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
        </div>
      </div>

      <hr style={{ margin: '18px 0' }} />

      <h4>Existing Academic Years</h4>
      {years.length === 0 ? (
        <div style={{ color: '#6b7280' }}>No academic years created yet.</div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
              <th style={{ padding: 8 }}>Academic Year</th>
              <th>Remaining Years</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {years.map((y) => (
              <tr key={y}>
                <td style={{ padding: 8 }}>{y}</td>
                <td>{remainingYears(y)}</td>
                <td>
                  <button onClick={() => handleRemove(y)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px', borderRadius: 4 }}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <div style={{ marginTop: 12, fontSize: 13, color: '#6b7280' }}>
        Academic years auto-expire after 6 years. You can later hook this to clean-up tasks in the backend.
      </div>
    </div>
  )
}
