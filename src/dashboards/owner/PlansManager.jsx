import React, { useEffect, useState } from 'react'
const KEY = 'app_plans_v1'
const CONFIG_KEY = 'app_owner_plans_config_v1' // owner-level dynamic settings
function read(key) { return JSON.parse(localStorage.getItem(key) || '[]') }
function save(key, list) { localStorage.setItem(key, JSON.stringify(list)) }

export default function PlansManager() {
  const [plans, setPlans] = useState([])
  const [form, setForm] = useState({ name: '', price: '', interval: 'monthly', image: '', video: '', maxStudents: 25 })
  const [msg, setMsg] = useState('')
  const [config, setConfig] = useState({ perStudentPrice: 30, freeThreshold: 25 })

  useEffect(() => {
    setPlans(read(KEY))
    const cfg = JSON.parse(localStorage.getItem(CONFIG_KEY) || 'null')
    if (cfg) setConfig(cfg)
  }, [])

  function show(t) { setMsg(t); setTimeout(() => setMsg(''), 3000) }

  function handleAdd() {
    if (!form.name.trim()) return show('Plan name required')
    const item = {
      id: 'plan_' + Date.now(),
      name: form.name.trim(),
      price: parseFloat(form.price) || 0,
      interval: form.interval,
      image: form.image || '',
      video: form.video || '',
      maxStudents: parseInt(form.maxStudents || 25, 10),
      createdAt: new Date().toISOString()
    }
    const updated = [item, ...read(KEY)]
    save(KEY, updated); setPlans(updated)
    setForm({ name: '', price: '', interval: 'monthly', image: '', video: '', maxStudents: config.freeThreshold || 25 })
    show('Plan created')
  }

  function handleRemove(id) {
    if (!confirm('Remove plan?')) return
    const updated = read(KEY).filter(p => p.id !== id)
    save(KEY, updated); setPlans(updated); show('Plan removed')
  }

  function exportCSV() {
    const rows = plans.map(p => `${p.id},${p.name},${p.price},${p.interval},${p.maxStudents}`)
    const csv = ['ID,Name,Price,Interval,MaxStudents', ...rows].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' }); const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'plans.csv'; a.click(); URL.revokeObjectURL(url)
  }

  function saveConfig() {
    const cfg = { perStudentPrice: parseFloat(config.perStudentPrice) || 30, freeThreshold: parseInt(config.freeThreshold || 25, 10) }
    localStorage.setItem(CONFIG_KEY, JSON.stringify(cfg)); setConfig(cfg); show('Pricing config saved')
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Subscription Plans</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 800 }}>
        <label>Plan name</label>
        <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Standard Monthly" />
        <label>Price (base)</label>
        <input value={form.price} onChange={e => setForm({ ...form, price: e.target.value })} placeholder="49.99" />
        <label>Interval</label>
        <select value={form.interval} onChange={e => setForm({ ...form, interval: e.target.value })}>
          <option value="monthly">Monthly</option>
          <option value="annual">Annual</option>
        </select>
        <label>Max Students included</label>
        <input type="number" value={form.maxStudents} onChange={e => setForm({ ...form, maxStudents: e.target.value })} />

        <label>Image URL</label>
        <input value={form.image} onChange={e => setForm({ ...form, image: e.target.value })} placeholder="https://..." />
        <label>Promo video URL</label>
        <input value={form.video} onChange={e => setForm({ ...form, video: e.target.value })} placeholder="https://..." />
      </div>

      <div style={{ marginTop: 12 }}>
        <button onClick={handleAdd} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>Add Plan</button>
        <button onClick={exportCSV} style={{ marginLeft: 8, padding: '8px 12px' }}>Export CSV</button>
        {msg && <span style={{ marginLeft: 12, color: '#10b981' }}>{msg}</span>}
      </div>

      <hr style={{ margin: '18px 0' }} />

      <h4>Plans</h4>
      {plans.length === 0 ? <div style={{ color: '#6b7280' }}>No plans yet.</div> : (
        <div>
          {plans.map(p => (
            <div key={p.id} style={{ border: '1px solid #eee', padding: 12, marginBottom: 8, borderRadius: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 'bold' }}>{p.name} — {p.interval}</div>
                  <div style={{ color: '#6b7280' }}>Price: {p.price} | Max students: {p.maxStudents}</div>
                  {p.image && <div style={{ marginTop: 8 }}><img src={p.image} alt="" style={{ maxWidth: 240 }} /></div>}
                  {p.video && <div style={{ marginTop: 8 }}><a href={p.video} target="_blank" rel="noreferrer">Promo video</a></div>}
                </div>
                <div>
                  <button onClick={() => handleRemove(p.id)} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '6px 8px' }}>Remove</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      <hr style={{ margin: '18px 0' }} />
      <h4>Owner Pricing Configuration</h4>
      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '200px 1fr', maxWidth: 640 }}>
        <label>Per-student price (when above included max)</label>
        <input value={config.perStudentPrice} onChange={e => setConfig({ ...config, perStudentPrice: e.target.value })} />
        <label>Default included students threshold</label>
        <input value={config.freeThreshold} onChange={e => setConfig({ ...config, freeThreshold: e.target.value })} />
      </div>
      <div style={{ marginTop: 12 }}>
<button onClick={saveConfig} style={{ padding: '8px 12px' }}>Save Pricing Config</button>
<div style={{ marginTop: 8, color: '#6b7280' }}>
  Per-student price applies when institute student count &gt; included max.
</div>
      </div>
    </div>
  )
}
