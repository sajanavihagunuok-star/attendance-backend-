import React, { useEffect, useState, useRef } from 'react'

const RADIUS_KEY = 'app_geofence_v1'

function readRadius() {
  return JSON.parse(localStorage.getItem(RADIUS_KEY) || '{}')
}
function saveRadius(payload) {
  localStorage.setItem(RADIUS_KEY, JSON.stringify(payload))
}

export default function AdminGeofence() {
  const [tracking, setTracking] = useState(false)
  const [lat, setLat] = useState('')
  const [lng, setLng] = useState('')
  const [radiusKm, setRadiusKm] = useState(0.5)
  const [msg, setMsg] = useState('')
  const watchIdRef = useRef(null)

  useEffect(() => {
    const saved = readRadius()
    if (saved && typeof saved.lat !== 'undefined') {
      setLat(String(saved.lat))
      setLng(String(saved.lng))
      setRadiusKm(saved.radiusKm || 0.5)
    }
    return () => stopTracking()
  }, [])

  function showMsg(t) {
    setMsg(t)
    setTimeout(() => setMsg(''), 3000)
  }

  function startTracking() {
    if (!navigator.geolocation) return showMsg('Geolocation not supported')
    setMsg('Starting live tracking…')
    const id = navigator.geolocation.watchPosition(
      (pos) => {
        setLat(String(pos.coords.latitude))
        setLng(String(pos.coords.longitude))
      },
      (err) => {
        showMsg('Unable to get location')
        console.error(err)
      },
      { enableHighAccuracy: true, maximumAge: 5000, timeout: 10000 }
    )
    watchIdRef.current = id
    setTracking(true)
  }

  function stopTracking() {
    if (watchIdRef.current !== null && navigator.geolocation) {
      navigator.geolocation.clearWatch(watchIdRef.current)
      watchIdRef.current = null
    }
    setTracking(false)
    showMsg('Stopped tracking')
  }

  function captureCurrent() {
    if (!navigator.geolocation) return showMsg('Geolocation not supported')
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setLat(String(pos.coords.latitude))
        setLng(String(pos.coords.longitude))
        showMsg('Captured current location')
      },
      () => showMsg('Unable to capture location')
    )
  }

  function handleSave() {
    const a = parseFloat(lat)
    const b = parseFloat(lng)
    const r = parseFloat(radiusKm)
    if (Number.isNaN(a) || Number.isNaN(b)) return showMsg('Valid coordinates required')
    if (Number.isNaN(r) || r <= 0) return showMsg('Radius must be > 0')
    saveRadius({ lat: a, lng: b, radiusKm: r })
    showMsg('Geofence saved')
    window.dispatchEvent(new Event('hashchange'))
  }

  return (
    <div style={{ padding: 12 }}>
      <h3>Geofence Live Tracking</h3>

      <div style={{ display: 'grid', gap: 8, gridTemplateColumns: '160px 1fr', maxWidth: 720 }}>
        <label>Latitude</label>
        <input value={lat} onChange={(e) => setLat(e.target.value)} placeholder="Latitude" />

        <label>Longitude</label>
        <input value={lng} onChange={(e) => setLng(e.target.value)} placeholder="Longitude" />

        <label>Radius (km)</label>
        <input type="number" step="0.1" value={radiusKm} onChange={(e) => setRadiusKm(e.target.value)} />

        <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8 }}>
          <button onClick={captureCurrent} style={{ padding: '8px 12px' }}>Capture Now</button>
          {!tracking ? (
            <button onClick={startTracking} style={{ padding: '8px 12px', background: '#0b79f7', color: '#fff', border: 'none', borderRadius: 6 }}>
              Start Live Tracking
            </button>
          ) : (
            <button onClick={stopTracking} style={{ padding: '8px 12px', background: '#ef4444', color: '#fff', border: 'none', borderRadius: 6 }}>
              Stop Live Tracking
            </button>
          )}
          <button onClick={handleSave} style={{ padding: '8px 12px', background: '#059669', color: '#fff', border: 'none', borderRadius: 6 }}>
            Save Geofence
          </button>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        {msg && <div style={{ color: '#10b981' }}>{msg}</div>}
        <div style={{ marginTop: 8, color: '#6b7280' }}>
          Live tracking uses browser geolocation. Keep location permission allowed for continuous updates.
        </div>
      </div>
    </div>
  )
}
