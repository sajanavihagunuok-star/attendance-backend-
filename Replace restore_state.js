// restore_state.js
import fs from 'fs'

const TOKEN = process.env.TOKEN
if (!TOKEN) {
  console.error('Set TOKEN environment variable before running: set TOKEN=your_token_here')
  process.exit(1)
}

if (!fs.existsSync('data.json')) {
  console.error('data.json not found. Run export_state.js before restarting the server.')
  process.exit(1)
}

const data = JSON.parse(fs.readFileSync('data.json', 'utf8'))

async function postJson(path, body, auth = true) {
  const headers = { 'Content-Type': 'application/json' }
  if (auth) headers.Authorization = `Bearer ${TOKEN}`
  const res = await fetch(`http://localhost:3000${path}`, { method: 'POST', headers, body: JSON.stringify(body) })
  const text = await res.text()
  let json
  try { json = JSON.parse(text) } catch { json = text }
  return { status: res.status, body: json }
}

async function main() {
  try {
    const created = {}
    for (const s of data.sessions || []) {
      const body = { courseCode: s.courseCode, courseName: s.courseName, startTs: s.start, durationMinutes: Math.round((s.end - s.start) / 60000) }
      const r = await postJson('/sessions', body, true)
      if (r.status === 200 || r.status === 201) {
        created[s.id] = r.body
        console.log('Recreated session', s.id, '->', r.body.id)
      } else {
        console.error('Failed to recreate session', s.id, r.status, r.body)
      }
    }

    for (const oldId of Object.keys(data.attendance || {})) {
      const records = data.attendance[oldId] || []
      const newSession = created[oldId]
      if (!newSession) {
        console.warn('Skipping attendance for session not recreated:', oldId)
        continue
      }
      const newId = newSession.id
      const pin = newSession.pin
      for (const rec of records) {
        const body = { studentId: rec.studentId, name: rec.name, pin }
        const r = await postJson(`/sessions/${newId}/attendance`, body, false)
        if (r.status === 200) {
          console.log('Restored attendance for', newId, rec.studentId)
        } else {
          console.error('Failed to restore attendance', newId, rec.studentId, r.status, r.body)
        }
      }
    }

    console.log('Restore finished')
  } catch (e) {
    console.error('Restore failed:', e.message)
    process.exit(3)
  }
}

main()
