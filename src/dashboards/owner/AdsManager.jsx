import React, { useEffect, useState } from 'react'
const KEY = 'app_ads_v1'
function read() { return JSON.parse(localStorage.getItem(KEY) || '[]') }
function save(list) { localStorage.setItem(KEY, JSON.stringify(list)) }

export default function AdsManager() {
  const [ads, setAds] = useState([])
  const [form, setForm] = useState({ title: '', url: '', visible: true })

  useEffect(() => setAds(read()), [])

  function handleAdd() {
    if (!form.title.trim()) return alert('Title required')
    const item = { id: 'ad_' + Date.now(), title: form.title.trim(), url: form.url, visible: !!form.visible, createdAt: new Date().toISOString() }
    const updated = [item, ...read()]; save(updated); setAds(updated); setForm({ title: '', url: '', visible: true })
  }

  function toggle(id) {
    const updated = read().map(a => a.id === id ? { ...a, visible: !a.visible } : a); save(updated); setAds(updated)
  }

  function remove(id) {
    if (!confirm('Remove ad?')) return
    const updated = read().filter(a => a.id !== id); save(updated); setAds(updated)
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Ads Manager</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 720 }}>
        <label>Title</label>
        <input value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
        <label>Destination URL</label>
        <input value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} />
        <label>Visible</label>
        <select value={String(form.visible)} onChange={e => setForm({ ...form, visible: e.target.value === 'true' })}>
          <option value="true">Yes</option><option value="false">No</option>
        </select>
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAdd} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Ad</button>
      </div>

      <hr style={{ margin: '18px 0' }} />

      {ads.length === 0 ? <div style={{ color: '#6b7280' }}>No ads.</div> : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead><tr style={{ textAlign: 'left', borderBottom: '1px solid #eee' }}>
            <th style={{ padding: 8 }}>Title</th><th>URL</th><th>Visible</th><th>Action</th>
          </tr></thead>
          <tbody>
            {ads.map(a => (
              <tr key={a.id}>
                <td style={{ padding: 8 }}>{a.title}</td>
                <td>{a.url || '-'}</td>
                <td>{a.visible ? 'Yes' : 'No'}</td>
                <td>
                  <button onClick={() => toggle(a.id)} style={{ marginRight: 8 }}>{a.visible ? 'Hide' : 'Show'}</button>
                  <button onClick={() => remove(a.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>Remove</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
