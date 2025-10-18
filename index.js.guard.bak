// Defensive wrapper to ensure actor id is a string or null
async function auditSafe(action, entity, actorId, payload) {
  try {
    // normalize actorId if an object with id or if non-string
    let actor_user_id = null;
    if (actorId) {
      if (typeof actorId === 'string') actor_user_id = actorId;
      else if (typeof actorId === 'object' && actorId.id) actor_user_id = actorId.id;
    }
    // call original auditSafe(assumes original function name is audit)
    return await auditSafe(action, entity, actor_user_id, payload);
  } catch (e) {
    console.error('auditSafe error', e);
    return null;
  }
}
// index.js
require('dns').setDefaultResultOrder('ipv4first');
if (process.env.DEBUG_TLS === '1') {
  console.warn('DEBUG_TLS=1   certificate verification relaxed');
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { URL } = require('url');
const { randomUUID } = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const asyncHandler = require('express-async-handler');
const db = require('./db');

let verifyToken = (req, res, next) => next();
let requireAuth = (req, res, next) => next();
let requireRole = (role) => (req, res, next) => next();
try {
  const auth = require('./middleware/auth');
  verifyToken = auth.verifyToken || verifyToken;
  requireAuth = auth.requireAuth || requireAuth;
  requireRole = auth.requireRole || requireRole;
} catch (e) {
  console.warn('Auth middleware not found, using no-op stubs for local development');
}

const app = express();
const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in environment');
  process.exit(1);
}

// ---------------- helpers ----------------
function sanitizeRawBuffer(buf) {
  if (!buf || !buf.length) return buf;
  let start = 0;
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) start = 3;
  const rest = buf.slice(start);
  const iBrace = rest.indexOf(0x7b);
  const iBracket = rest.indexOf(0x5b);
  let i = -1;
  if (iBrace >= 0 && iBracket >= 0) i = Math.min(iBrace, iBracket);
  else i = Math.max(iBrace, iBracket);
  if (i >= 0) start = start + i;
  return buf.slice(start);
}
const isUuid = s => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const hash = async (pw) => await bcrypt.hash(pw, 10);
const compare = async (pw, h) => await bcrypt.compare(pw, h);
function signToken(payload) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign(payload, secret, { expiresIn: '12h' });
}
async function auditSafe(actorUserId, action, entityType, entityId, payload) {
  try {
    await db.query(
      'INSERT INTO audits(actor_user_id, action, entity_type, entity_id, payload) VALUES ($1,$2,$3,$4,$5)',
      [actorUserId, action, entityType, entityId, payload || {}]
    );
  } catch (e) {
    console.error('AUDIT-ERR', e && e.stack || e);
  }
}

// ---------------- middleware ----------------
app.use(cors());
app.use(express.json({
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      req._rawSanitized = sanitizeRawBuffer(buf).toString('utf8');
    } catch (e) {
      console.error('RAW-VERIFY-ERR', e && e.stack || e);
    }
  }
}));
app.use(express.urlencoded({ extended: false }));
app.use(verifyToken);

// ---------------- fallback JSON parser ----------------
app.use((req, res, next) => {
  try {
    if (!req.headers['content-type'] || !req.headers['content-type'].includes('application/json')) return next();
    if (req.body && Object.keys(req.body).length) return next();
    const raw = (req._rawSanitized || '').trim();
    if (!raw) return next();
    try {
      req.body = JSON.parse(raw);
      return next();
    } catch (e) { }
    if (raw.length > 2000) return next();
    let t = raw.trim();
    if (!t.startsWith('{') && !t.startsWith('[')) t = '{' + t + '}';
    t = t.replace(/([{,]\s*)([A-Za-z0-9_@.\-]+)\s*:/g, '$1"$2":');
    t = t.replace(/:\s*([A-Za-z0-9_@.\-\/:+]+)(\s*[,\}])/g, (m, val, tail) => {
      if (/^(true|false|null|\d+(\.\d+)?)$/i.test(val)) return ':' + val + tail;
      if (val[0] === '"' || val[0] === "'") return ':' + val + tail;
      const escaped = String(val).replace(/"/g, '\\"');
      return ':"' + escaped + '"' + tail;
    });
    try {
      req.body = JSON.parse(t);
      req._forcedParsed = true;
      return next();
    } catch (ee) {
      console.error('FALLBACK-PARSE-ERR', ee && ee.stack || ee);
      return next();
    }
  } catch (outer) {
    console.error('FALLBACK-ERR', outer && outer.stack || outer);
    return next();
  }
});

// ---------------- rate limiters ----------------
const qrRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 6,
  message: { error: 'Too many QR requests, try again later' },
  standardHeaders: true,
  legacyHeaders: false
});
const qrInvalidateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many invalidate requests, try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// ---------------- health check ----------------
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ---------------- routes ----------------

// Institutes
app.post('/institutes', asyncHandler(async (req, res) => {
  const { name, domain } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await db.query(
    'INSERT INTO institutes(id,name,domain,created_at) VALUES (gen_random_uuid(), $1, $2, now()) RETURNING *',
    [name, domain || null]
  );
  res.json({ institute: rows[0] });
}));

// Auth register
app.post('/auth/register', asyncHandler(async (req, res) => {
  const { email, password, institute_id, role, full_name } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const hashed = await hash(password);
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const ures = await client.query(
      'INSERT INTO users(id,institute_id,email,password_hash,role,created_at) VALUES (gen_random_uuid(), $1, $2, $3, $4, now()) RETURNING *',
      [institute_id || null, email.toLowerCase(), hashed, role || 'student']
    );
    const user = ures.rows[0];
    if (full_name) {
      await client.query('INSERT INTO profiles(user_id,full_name,created_at) VALUES ($1,$2,now())', [user.id, full_name]);
    }
    await auditSafe(user.id, 'register', 'user', user.id, { email, institute_id, role });
    await client.query('COMMIT');
    const token = signToken({ sub: user.id, role: user.role, email: user.email, institute_id: user.institute_id });
    res.json({ user, token });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'user exists' });
    throw err;
  } finally {
    client.release();
  }
}));

// Auth login
app.post('/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const { rows } = await db.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email.toLowerCase()]);
  if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  if (!user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({ sub: user.id, role: user.role, email: user.email, institute_id: user.institute_id });
  await auditSafe(user.id, 'login', 'user', user.id, {});
  res.json({ user: { id: user.id, email: user.email, role: user.role, institute_id: user.institute_id }, token });
}));

// Courses
app.post('/courses', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await db.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const { code, name, description } = req.body || {};
  if (!code || !name) return res.status(400).json({ error: 'code and name required' });
  try {
    const q = 'INSERT INTO courses(id,institute_id,code,name,description,created_at) VALUES (gen_random_uuid(), $1, $2, $3, $4, now()) RETURNING *';
    const { rows } = await db.query(q, [actorRow.institute_id, code, name, description || null]);
    await auditSafe(actor.sub, 'create_course', 'course', rows[0].id, { code, name });
    res.json({ course: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Course code exists' });
    throw err;
  }
}));

app.get('/courses', requireAuth, asyncHandler(async (req, res) => {
  const institute_id = req.user && req.user.institute_id;
  const { rows } = await db.query('SELECT * FROM courses WHERE institute_id = $1 ORDER BY created_at DESC', [institute_id]);
  res.json({ courses: rows });
}));

app.get('/courses/lookup', asyncHandler(async (req, res) => {
  const code = (req.query.code || '').trim();
  const institute_id = req.query.institute_id || (req.user && req.user.institute_id);
  if (!code) return res.status(400).json({ error: 'code required' });
  const { rows } = await db.query('SELECT * FROM courses WHERE institute_id = $1 AND code = $2 LIMIT 1', [institute_id, code]);
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json({ course: rows[0] });
}));

app.get('/courses/:id', requireAuth, asyncHandler(async (req, res) => {
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
  const { rows } = await db.query('SELECT * FROM courses WHERE id = $1 LIMIT 1', [id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json({ course: rows[0] });
}));

app.put('/courses/:id', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await db.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const id = req.params.id;
  const { name, description, code } = req.body || {};
  if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
  const { rows } = await db.query('UPDATE courses SET name=$1, description=$2, code=$3, updated_at=now() WHERE id=$4 RETURNING *', [name, description || null, code, id]);
  res.json({ course: rows[0] });
}));

app.delete('/courses/:id', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await db.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
  await db.query('DELETE FROM courses WHERE id=$1', [id]);
  res.json({ deleted: id });
}));

// Batches
app.post('/batches', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await db.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await db.query('INSERT INTO batches(id,institute_id,name,created_at) VALUES (gen_random_uuid(), $1, $2, now()) RETURNING *', [actorRow.institute_id, name]);
  await auditSafe(actor.sub, 'create_batch', 'batch', rows[0].id, { name });
  res.json({ batch: rows[0] });
}));

app.get('/batches', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await db.query('SELECT * FROM batches WHERE institute_id = $1 ORDER BY created_at DESC', [inst]);
  res.json({ batches: rows });
}));

// Enrollments
app.post('/enrollments', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await db.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const { student_id, course_id, batch_id } = req.body || {};
  if (!student_id || !course_id) return res.status(400).json({ error: 'student_id and course_id required' });
  const { rows } = await db.query('INSERT INTO enrollments(id,student_id,course_id,batch_id,created_at) VALUES (gen_random_uuid(), $1, $2, $3, now()) RETURNING *', [student_id, course_id, batch_id || null]);
  await auditSafe(actor.sub, 'enroll', 'enrollment', rows[0].id, { student_id, course_id, batch_id });
  res.json({ enrollment: rows[0] });
}));

app.get('/enrollments', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await db.query(`
    SELECT e.*, p.full_name, c.code, c.name as course_name FROM enrollments e
    LEFT JOIN profiles p ON p.id = e.student_id
    LEFT JOIN courses c ON c.id = e.course_id
    WHERE c.institute_id = $1 ORDER BY e.created_at DESC
  `, [inst]);
  res.json({ enrollments: rows });
}));

// Profiles
app.get('/profiles', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await db.query('SELECT * FROM profiles WHERE (user_id IS NULL OR user_id IN (SELECT id FROM users WHERE institute_id = $1)) ORDER BY created_at DESC LIMIT 1000', [inst]);
  res.json({ profiles: rows });
}));

app.post('/profiles', asyncHandler(async (req, res) => {
  const { id, full_name, user_id, is_teacher, batch_id } = req.body || {};
  const q = `INSERT INTO profiles(id, user_id, full_name, is_teacher, batch_id, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5, now(), now()) RETURNING *`;
  const params = [id || randomUUID(), user_id || null, full_name || null, !!is_teacher, batch_id || null];
  const { rows } = await db.query(q, params);
  res.json({ profile: rows[0] });
}));

// Sessions
app.post('/sessions', requireAuth, asyncHandler(async (req, res) => {
  const isAdmin = req.user && ['admin','super_admin','owner'].includes(req.user.role);
  const isLecturer = req.user && req.user.role === 'lecturer';
  if (!isAdmin && !isLecturer) return res.status(403).json({ error: 'Admin or lecturer required' });
  const incoming = req.body || {};
  const { title, course_id, lecturer_id, start_time } = incoming;
  const missing = [];
  if (!title) missing.push('title');
  if (!course_id) missing.push('course_id');
  if (!start_time) missing.push('start_time');
  if (!lecturer_id) missing.push('lecturer_id');
  if (missing.length) return res.status(400).json({ error: 'Missing required fields', missing });
  if (!isUuid(course_id)) return res.status(400).json({ error: 'invalid course_id' });
  if (!isUuid(lecturer_id)) return res.status(400).json({ error: 'invalid lecturer_id' });
  const q = `INSERT INTO sessions(id,title,course_id,start_time,end_time,lecturer_id,capacity,created_at)
             VALUES (gen_random_uuid(), $1, $2, $3::timestamptz, $4::timestamptz, $5, $6, now()) RETURNING *`;
  const params = [title, course_id, start_time, incoming.end_time || null, lecturer_id, incoming.capacity || null];
  const { rows } = await db.query(q, params);
  res.json({ session: rows[0] });
}));

// QR / PIN
app.post('/qr', qrRateLimiter, asyncHandler(async (req, res) => {
  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ error: 'session_id required' });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const { rows: srows } = await db.query('SELECT id, course_id, lecturer_id, start_time FROM sessions WHERE id = $1 LIMIT 1', [session_id]);
  if (!srows[0]) return res.status(404).json({ error: 'Session not found' });
  const sess = srows[0];
  if (!sess.course_id || !sess.lecturer_id || !sess.start_time) return res.status(400).json({ error: 'Session missing required details. Fill course, lecturer and start_time before generating QR.' });
  const existing = (await db.query('SELECT * FROM session_qr WHERE session_id=$1 AND expires_at >= now() ORDER BY created_at DESC LIMIT 1', [session_id])).rows[0];
  if (existing) return res.json({ qr: existing, note: 'existing_active' });
  const pin = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  const q = `INSERT INTO session_qr(session_id, pin, expires_at) VALUES ($1, $2, $3) RETURNING *`;
  const { rows } = await db.query(q, [session_id, pin, expiresAt]);
  res.json({ qr: { session_id, pin: rows[0].pin, expires_at: rows[0].expires_at, created_at: rows[0].created_at } });
}));

app.get('/qr/:session_id', asyncHandler(async (req, res) => {
  const session_id = req.params.session_id;
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const { rows } = await db.query('SELECT * FROM session_qr WHERE session_id = $1 AND expires_at >= now() ORDER BY created_at DESC LIMIT 1', [session_id]);
  res.json({ qr: rows[0] || null });
}));

app.post('/qr/invalidate', qrInvalidateLimiter, requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await db.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin','lecturer'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin or lecturer required' });
  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ error: 'session_id required' });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const del = await db.query('DELETE FROM session_qr WHERE session_id = $1 RETURNING *', [session_id]);
  await auditSafe(actor.sub, 'invalidate_qr', 'session_qr', session_id, { invalidated: del.rows.length });
  res.json({ invalidated: del.rows.length, rows: del.rows });
}));

app.get('/_internal/db-check', async (req, res) => {
  const { rows } = await db.query('SELECT now() as now');
  res.json({ ok: true, now: rows[0].now });
});

// ---------------- start server ----------------
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});




