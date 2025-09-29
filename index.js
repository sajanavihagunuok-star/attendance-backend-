// backend/index.js
import express from 'express'
import cors from 'cors'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

dotenv.config()
const app = express()
app.use(cors())
app.use(express.json())

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET || 'replace_me'
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d'

// In-memory stores for MVP. Replace with DB later.
const users = []            // { id, email, passwordHash, displayName, role }
const subjects = []         // { code, title, description, batch, year }
const sessions = []         // { id, courseCode, courseName, start, end, pin, createdBy }
const attendance = {}       // key: sessionId -> [records]

// Helpers
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization
  if (!auth) return res.status(401).json({ error: 'Missing authorization' })
  const parts = auth.split(' ')
  if (parts.length !== 2) return res.status(401).json({ error: 'Invalid authorization format' })
  const token = parts[1]
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    req.user = payload
    next()
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

// Routes
app.get('/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV || 'dev' }))

// Auth
app.post('/auth/register', async (req, res) => {
  const { email, password, displayName, role = 'lecturer' } = req.body
  if (!email || !password) return res.status(400).json({ error: 'email and password required' })
  if (users.find(u => u.email === email)) return res.status(400).json({ error: 'User exists' })
  const salt = bcrypt.genSaltSync(10)
  const hash = bcrypt.hashSync(password, salt)
  const user = { id: 'u_' + Date.now(), email, passwordHash: hash, displayName: displayName || email, role }
  users.push(user)
  const token = generateToken(user)
  res.json({ user: { id: user.id, email: user.email, displayName: user.displayName, role: user.role }, token })
})

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'email and password required' })
  const user = users.find(u => u.email === email)
  if (!user) return res.status(400).json({ error: 'Invalid credentials' })
  const ok = bcrypt.compareSync(password, user.passwordHash)
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' })
  const token = generateToken(user)
  res.json({ user: { id: user.id, email: user.email, displayName: user.displayName, role: user.role }, token })
})

// Subjects (admin)
app.get('/subjects', authMiddleware, (req, res) => {
  res.json(subjects)
})
app.post('/subjects', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' })
  const { code, title, description, batch, year } = req.body
  if (!code || !title) return res.status(400).json({ error: 'code and title required' })
  const upper = code.toUpperCase()
  const existing = subjects.find(s => s.code === upper)
  const item = { code: upper, title, description: description || '', batch: batch || '', year: year || '' }
  if (existing) {
    Object.assign(existing, item)
    return res.json(existing)
  }
  subjects.push(item)
  res.json(item)
})

// Sessions
app.post('/sessions', authMiddleware, (req, res) => {
  const { courseCode, courseName, startTs, durationMinutes } = req.body
  if (!courseCode || !courseName || !startTs || !durationMinutes) return res.status(400).json({ error: 'missing fields' })
  const id = 's_' + Date.now()
  const pin = String(Math.floor(10000 + Math.random() * 90000))
  const start = Number(startTs)
  const end = start + Number(durationMinutes) * 60000
  const session = { id, courseCode: courseCode.toUpperCase(), courseName, start, end, pin, createdBy: req.user.id }
  sessions.push(session)
  attendance[session.id] = []
  res.json(session)
})

app.get('/sessions', authMiddleware, (req, res) => {
  res.json(sessions)
})

// Attendance handlers (fixed)
app.post('/sessions/:id/attendance', (req, res) => {
  const sessionId = req.params.id
  const { studentId, name, pin } = req.body || {}
  const s = sessions.find(x => x.id === sessionId)
  if (!s) return res.status(404).json({ error: 'session not found' })
  if (String(s.pin) !== String(pin)) return res.status(400).json({ error: 'incorrect pin' })
  const rec = { studentId, name: name || '', markedAt: Date.now(), pin }
  attendance[sessionId] = attendance[sessionId] || []
  attendance[sessionId].push(rec)
  return res.json({ ok: true, record: rec })
})

app.get('/sessions/:id/attendance', authMiddleware, (req, res) => {
  const sessionId = req.params.id
  return res.json(attendance[sessionId] || [])
})

// Dev-only bootstrap admin (remove in production)
app.post('/_bootstrap/admin', (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ error: 'email/password required' })
  const salt = bcrypt.genSaltSync(10)
  const hash = bcrypt.hashSync(password, salt)
  const user = { id: 'u_admin_' + Date.now(), email, passwordHash: hash, displayName: 'Admin', role: 'admin' }
  users.push(user)
  res.json({ ok: true, user: { id: user.id, email: user.email } })
})

// Simple error handler
app.use((err, req, res, next) => {
  console.error(err)
  res.status(500).json({ error: 'server error' })
})

app.listen(PORT, () => console.log(`API listening on port ${PORT}`))
