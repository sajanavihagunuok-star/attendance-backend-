// export_state.js
import fs from 'fs'

const TOKEN = process.env.TOKEN
if (!TOKEN) {
  console.error('Set TOKEN environment variable before running: set TOKEN=your_token_here')
  process.exit(1)
}

async function getJson(path) {
  const res = await fetch(`http://localhost:3000${path}`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  if (!res.ok) throw new Error(`${path} -> ${res.status} ${await res.text()}`)
  return res.json()
}

async function main() {
  try {
    const sessions = await getJson('/sessions')
    const attendancePromises = sessions.map(s => getJson(`/sessions/${s.id}/attendance`).catch(()=>[]))
    const attendanceArrays = await Promise.all(attendancePromises)
    const attendance = {}
    sessions.forEach((s, i) => { attendance[s.id] = attendanceArrays[i] || [] })
    const out = { exportedAt: Date.now(), sessions, attendance }
    fs.writeFileSync('data.json', JSON.stringify(out, null, 2), 'utf8')
    console.log('Saved data.json with', sessions.length, 'sessions')
  } catch (e) {
    console.error('Export failed:', e.message)
    process.exit(2)
  }
}

main()
