import React, { useEffect, useState } from 'react'

const KEY = 'app_institute_branding_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '{}') }
function save(obj) { localStorage.setItem(KEY, JSON.stringify(obj)) }

export default function SABranding() {
  const [branding, setBranding] = useState({ name: '', color: '#0b79f7', logo: '' })
  useEffect(() => setBranding(read()), [])

  function handleSave() {
    save(branding); alert('Branding saved (local demo)')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Branding</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 720 }}>
        <label>Institute name (for preview)</label>
        <input value={branding.name} onChange={e => setBranding({ ...branding, name: e.target.value })} />
        <label>Primary color (hex)</label>
        <input value={branding.color} onChange={e => setBranding({ ...branding, color: e.target.value })} />
        <label>Logo URL</label>
        <input value={branding.logo} onChange={e => setBranding({ ...branding, logo: e.target.value })} placeholder="https://..." />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleSave} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff' }}>Save Branding</button>
        <button onClick={() => window.alert(JSON.stringify(branding, null, 2))} style={{ marginLeft: 8, padding: '8px 12px' }}>Save and Preview</button>
      </div>
    </div>
  )
}
