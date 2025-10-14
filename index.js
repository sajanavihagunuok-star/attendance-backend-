// index.js — complete server file (copy-paste ready)
// Forces IPv4 A record for DB connections; remove /_internal/db-check and DEBUG_TLS after debugging
require('dns').setDefaultResultOrder('ipv4first');

if (process.env.DEBUG_TLS === '1') {
  console.warn('DEBUG_TLS=1 — certificate verification relaxed');
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { URL } = require('url');
const dns = require('dns').promises;
const { randomUUID } = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const asyncHandler = require('express-async-handler');

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

// ---------------- helpers ----------------
function sanitizeRawBuffer(buf) {
  if (!buf || !buf.length) return buf;
  let start = 0;
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) start = 3;
  const rest = buf.slice(start);
  const iBrace = rest.indexOf(0x7b); // '{'
  const iBracket = rest.indexOf(0x5b); // '['
  let i = -1;
  if (iBrace >= 0 && iBracket >= 0) i = Math.min(iBrace, iBracket);
  else i = Math.max(iBrace, iBracket);
  if (i >= 0) start = start + i;
  return buf.slice(start);
}
const isUuid = s => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);

// ---------------- parsing middlewares ----------------
app.use(cors());
app.use(express.json({
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      req._rawSanitized = sanitizeRawBuffer(buf).toString('utf8');
      if (process.env.DEBUG_RAW === '1') {
        console.log('RAW-INCOMING-TEXT', req._rawSanitized);
        console.log('RAW-INCOMING-HEX', Buffer.from(buf).toString('hex'));
      }
    } catch (e) {
      console.error('RAW-VERIFY-ERR', e && e.stack || e);
    }
  }
}));
app.use(express.urlencoded({ extended: false }));
app.use(verifyToken);

// ---------------- conservative fallback parser ----------------
app.use((req, res, next) => {
  try {
    if (!req.headers['content-type'] || !req.headers['content-type'].includes('application/json')) return next();
    if (req.body && Object.keys(req.body).length) return next();
    const raw = (req._rawSanitized || '').trim();
    if (!raw) return next();
    try {
      req.body = JSON.parse(raw);
      return next();
    } catch (e) { /* continue */ }
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

// ---------------- config ----------------
const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in environment');
  process.exit(1);
}

// ---------------- create pool forcing IPv4 A record ----------------
async function createPoolFromEnvForceIPv4() {
  const raw = process.env.DATABASE_URL;
  if (!raw) throw new Error('Missing DATABASE_URL in environment');
  const parsed = new URL(raw.startsWith('postgres') ? raw : 'postgresql:' + raw);
  // resolve A records only
  let addrs;
  try {
    addrs = await dns.resolve4(parsed.hostname);
  } catch (e) {
    console.error('IPv4 resolve failed for host', parsed.hostname, e && e.message);
    throw new Error('No IPv4 address found for DB host: ' + parsed.hostname);
  }
  if (!addrs || !addrs.length) throw new Error('No IPv4 address found for DB host: ' + parsed.hostname);
  const ipv4 = addrs[0];
  const auth = parsed.username ? (parsed.username + (parsed.password ? ':' + parsed.password : '') + '@') : '';
  const rebuilt = `${parsed.protocol}//${auth}${ipv4}${parsed.port ? ':' + parsed.port : ''}${parsed.pathname}${parsed.search || ''}`;
  return new Pool({
    connectionString: rebuilt,
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 10000,
    ssl: (process.env.DEBUG_TLS === '1') ? { rejectUnauthorized: false } : { rejectUnauthorized: true }
  });
}

let pool;
createPoolFromEnvForceIPv4().then(p => { pool = p; console.log('DB pool created using IPv4'); }).catch(err => {
  console.error('FATAL: cannot create DB pool (no IPv4)', err && err.stack || err);
  process.exit(1);
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

// ---------------- utility helpers ----------------
const hash = async (pw) => await bcrypt.hash(pw, 10);
const compare = async (pw, h) => await bcrypt.compare(pw, h);
function signToken(payload) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign(payload, secret, { expiresIn: '12h' });
}
async function audit(actorUserId, action, entityType, entityId, payload) {
  try {
    await pool.query(
      'INSERT INTO audits(actor_user_id, action, entity_type, entity_id, payload) VALUES ($1,$2,$3,$4,$5)',
      [actorUserId, action, entityType, entityId, payload || {}]
    );
  } catch (e) {
    console.error('AUDIT-ERR', e && e.stack || e);
  }
}

// ---------------- temporary internal DB check (remove after use) ----------------
app.get('/_internal/db-check', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT NOW() as now');
    return res.json({ ok: true, now: rows[0].now.toString() });
  } catch (err) {
    console.error('REMOTE-DB-CHECK-ERR', err && err.stack || err);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ---------------- routes ----------------

// Institutes
app.post('/institutes', asyncHandler(async (req, res) => {
  const { name, domain } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await pool.query(
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
  const client = await pool.connect();
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
    await audit(user.id, 'register', 'user', user.id, { email, institute_id, role });
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
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email.toLowerCase()]);
  if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  if (!user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({ sub: user.id, role: user.role, email: user.email, institute_id: user.institute_id });
  await audit(user.id, 'login', 'user', user.id, {});
  res.json({ user: { id: user.id, email: user.email, role: user.role, institute_id: user.institute_id }, token });
}));

// Courses
app.post('/courses', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const { code, name, description } = req.body || {};
  if (!code || !name) return res.status(400).json({ error: 'code and name required' });
  try {
    const q = 'INSERT INTO courses(id,institute_id,code,name,description,created_at) VALUES (gen_random_uuid(), $1, $2, $3, $4, now()) RETURNING *';
    const { rows } = await pool.query(q, [actorRow.institute_id, code, name, description || null]);
    await audit(actor.sub, 'create_course', 'course', rows[0].id, { code, name });
    res.json({ course: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Course code exists' });
    throw err;
  }
}));

app.get('/courses', requireAuth, asyncHandler(async (req, res) => {
  const institute_id = req.user && req.user.institute_id;
  const { rows } = await pool.query('SELECT * FROM courses WHERE institute_id = $1 ORDER BY created_at DESC', [institute_id]);
  res.json({ courses: rows });
}));

app.get('/courses/lookup', asyncHandler(async (req, res) => {
  const code = (req.query.code || '').trim();
  const institute_id = req.query.institute_id || (req.user && req.user.institute_id);
  if (!code) return res.status(400).json({ error: 'code required' });
  const { rows } = await pool.query('SELECT * FROM courses WHERE institute_id = $1 AND code = $2 LIMIT 1', [institute_id, code]);
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json({ course: rows[0] });
}));

app.get('/courses/:id', requireAuth, asyncHandler(async (req, res) => {
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
  const { rows } = await pool.query('SELECT * FROM courses WHERE id = $1 LIMIT 1', [id]);
  if (!rows[0]) return res.status(404).json({ error: 'not found' });
  res.json({ course: rows[0] });
}));

app.put('/courses/:id', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const id = req.params.id;
  const { name, description, code } = req.body || {};
  if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
  const { rows } = await pool.query('UPDATE courses SET name=$1, description=$2, code=$3, updated_at=now() WHERE id=$4 RETURNING *', [name, description || null, code, id]);
  res.json({ course: rows[0] });
}));

app.delete('/courses/:id', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'invalid id' });
  await pool.query('DELETE FROM courses WHERE id=$1', [id]);
  res.json({ deleted: id });
}));

// Batches
app.post('/batches', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await pool.query('INSERT INTO batches(id,institute_id,name,created_at) VALUES (gen_random_uuid(), $1, $2, now()) RETURNING *', [actorRow.institute_id, name]);
  await audit(actor.sub, 'create_batch', 'batch', rows[0].id, { name });
  res.json({ batch: rows[0] });
}));

app.get('/batches', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await pool.query('SELECT * FROM batches WHERE institute_id = $1 ORDER BY created_at DESC', [inst]);
  res.json({ batches: rows });
}));

// Enrollments
app.post('/enrollments', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });
  const { student_id, course_id, batch_id } = req.body || {};
  if (!student_id || !course_id) return res.status(400).json({ error: 'student_id and course_id required' });
  const { rows } = await pool.query('INSERT INTO enrollments(id,student_id,course_id,batch_id,created_at) VALUES (gen_random_uuid(), $1, $2, $3, now()) RETURNING *', [student_id, course_id, batch_id || null]);
  await audit(actor.sub, 'enroll', 'enrollment', rows[0].id, { student_id, course_id, batch_id });
  res.json({ enrollment: rows[0] });
}));

app.get('/enrollments', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await pool.query(`
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
  const { rows } = await pool.query('SELECT * FROM profiles WHERE (user_id IS NULL OR user_id IN (SELECT id FROM users WHERE institute_id = $1)) ORDER BY created_at DESC LIMIT 1000', [inst]);
  res.json({ profiles: rows });
}));

app.post('/profiles', asyncHandler(async (req, res) => {
  const { id, full_name, user_id, is_teacher, batch_id } = req.body || {};
  const q = `INSERT INTO profiles(id, user_id, full_name, is_teacher, batch_id, created_at, updated_at)
             VALUES ($1,$2,$3,$4,$5, now(), now()) RETURNING *`;
  const params = [id || randomUUID(), user_id || null, full_name || null, !!is_teacher, batch_id || null];
  const { rows } = await pool.query(q, params);
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
  const { rows } = await pool.query(q, params);
  res.json({ session: rows[0] });
}));

// QR / PIN
app.post('/qr', qrRateLimiter, asyncHandler(async (req, res) => {
  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ error: 'session_id required' });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const { rows: srows } = await pool.query('SELECT id, course_id, lecturer_id, start_time FROM sessions WHERE id = $1 LIMIT 1', [session_id]);
  if (!srows[0]) return res.status(404).json({ error: 'Session not found' });
  const sess = srows[0];
  if (!sess.course_id || !sess.lecturer_id || !sess.start_time) return res.status(400).json({ error: 'Session missing required details. Fill course, lecturer and start_time before generating QR.' });
  const existing = (await pool.query('SELECT * FROM session_qr WHERE session_id=$1 AND expires_at >= now() ORDER BY created_at DESC LIMIT 1', [session_id])).rows[0];
  if (existing) return res.json({ qr: existing, note: 'existing_active' });
  const pin = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  const q = `INSERT INTO session_qr(session_id, pin, expires_at) VALUES ($1, $2, $3) RETURNING *`;
  const { rows } = await pool.query(q, [session_id, pin, expiresAt]);
  res.json({ qr: { session_id, pin: rows[0].pin, expires_at: rows[0].expires_at, created_at: rows[0].created_at } });
}));

app.get('/qr/:session_id', asyncHandler(async (req, res) => {
  const session_id = req.params.session_id;
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const { rows } = await pool.query('SELECT * FROM session_qr WHERE session_id = $1 AND expires_at >= now() ORDER BY created_at DESC LIMIT 1', [session_id]);
  res.json({ qr: rows[0] || null });
}));

app.post('/qr/invalidate', qrInvalidateLimiter, requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin','lecturer'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin or lecturer required' });
  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ error: 'session_id required' });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const del = await pool.query('DELETE FROM session_qr WHERE session_id = $1 RETURNING *', [session_id]);
  await audit(actor.sub, 'invalidate_qr', 'session_qr', session_id, { invalidated: del.rows.length });
  res.json({ invalidated: del.rows.length, rows: del.rows });
}));

// Attendance
app.post('/attendance', asyncHandler(async (req, res) => {
  const { session_id, student_id, attended, pin } = req.body || {};
  if (!session_id || !student_id) return res.status(400).json({ error: 'Missing fields', missing: ['session_id','student_id'] });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  if (!isUuid(student_id)) return res.status(400).json({ error: 'invalid student_id' });
  const isAdminOrLecturer = req.user && ['admin','lecturer','super_admin','owner'].includes(req.user.role);
  if (!isAdminOrLecturer) {
    if (!pin) return res.status(403).json({ error: 'PIN required for marking attendance' });
    const { rows: pinRows } = await pool.query('SELECT * FROM session_qr WHERE session_id = $1 AND pin = $2 ORDER BY created_at DESC LIMIT 1', [session_id, String(pin)]);
    if (!pinRows[0]) return res.status(403).json({ error: 'Invalid PIN' });
    if (new Date(pinRows[0].expires_at) < new Date()) return res.status(403).json({ error: 'PIN expired' });
  }
  const q = `INSERT INTO attendance(id, session_id, student_id, attended, marked_at) VALUES (gen_random_uuid(), $1, $2, $3, now()) RETURNING *`;
  const { rows } = await pool.query(q, [session_id, student_id, !!attended]);
  res.json({ attendance: rows[0] });
}));

app.get('/attendance', asyncHandler(async (req, res) => {
  const { student_id, batch_id, subject_id, date_from, date_to, session_id } = req.query;
  let q = `SELECT a.*, s.course_id, p.batch_id FROM attendance a
           LEFT JOIN sessions s ON s.id = a.session_id
           LEFT JOIN profiles p ON p.id = a.student_id
           WHERE true`;
  const params = [];
  let i = 1;
  if (session_id) { if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' }); q += ` AND a.session_id = $${i++}`; params.push(session_id); }
  if (student_id) { q += ` AND a.student_id = $${i++}`; params.push(student_id); }
  if (batch_id) { q += ` AND p.batch_id = $${i++}`; params.push(batch_id); }
  if (subject_id) { q += ` AND s.course_id = $${i++}`; params.push(subject_id); }
  if (date_from) { q += ` AND a.marked_at >= $${i++}`; params.push(date_from); }
  if (date_to) { q += ` AND a.marked_at <= $${i++}`; params.push(date_to); }
  q += ' ORDER BY a.marked_at DESC LIMIT 1000';
  const { rows } = await pool.query(q, params);
  res.json({ attendance: rows });
}));

app.get('/attendance/export', asyncHandler(async (req, res) => {
  const { student_id, batch_id, subject_id, date_from, date_to, session_id } = req.query;
  let q = `SELECT a.id as attendance_id, a.session_id, s.title as session_title, s.course_id, c.code as course_code, c.name as course_name,
                  a.student_id, p.full_name as student_name, p.batch_id, a.attended, a.marked_at
           FROM attendance a
           LEFT JOIN sessions s ON s.id = a.session_id
           LEFT JOIN courses c ON c.id = s.course_id
           LEFT JOIN profiles p ON p.id = a.student_id
           WHERE true`;
  const params = [];
  let i = 1;
  if (session_id) { if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' }); q += ` AND a.session_id = $${i++}`; params.push(session_id); }
  if (student_id) { if (!isUuid(student_id)) return res.status(400).json({ error: 'invalid student_id' }); q += ` AND a.student_id = $${i++}`; params.push(student_id); }
  if (batch_id) { q += ` AND p.batch_id = $${i++}`; params.push(batch_id); }
  if (subject_id) { q += ` AND s.course_id = $${i++}`; params.push(subject_id); }
  if (date_from) { q += ` AND a.marked_at >= $${i++}`; params.push(date_from); }
  if (date_to) { q += ` AND a.marked_at <= $${i++}`; params.push(date_to); }
  q += ' ORDER BY a.marked_at DESC LIMIT 5000';
  const { rows } = await pool.query(q, params);

  function escapeCsv(val) {
    if (val === null || val === undefined) return '';
    const s = String(val);
    if (s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  }

  const header = ['attendance_id','session_id','session_title','course_id','course_code','course_name','student_id','student_name','batch_id','attended','marked_at'];
  const csvLines = [header.join(',')];
  for (const r of rows) {
    const line = [
      r.attendance_id,
      r.session_id,
      escapeCsv(r.session_title),
      r.course_id,
      escapeCsv(r.course_code),
      escapeCsv(r.course_name),
      r.student_id,
      escapeCsv(r.student_name),
      r.batch_id,
      r.attended ? '1' : '0',
      r.marked_at ? new Date(r.marked_at).toISOString() : ''
    ].join(',');
    csvLines.push(line);
  }

  const csv = csvLines.join('\n');
  res.setHeader('Content-Disposition', 'attachment; filename=attendance_export.csv');
  res.setHeader('Content-Type', 'text/csv');
  res.send(csv);
}));

// Debug counters
app.get('/_debug/counters', asyncHandler(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT
      (SELECT count(*) FROM institutes) AS institutes,
      (SELECT count(*) FROM users) AS users,
      (SELECT count(*) FROM courses) AS courses,
      (SELECT count(*) FROM sessions) AS sessions,
      (SELECT count(*) FROM attendance) AS attendance,
      (SELECT count(*) FROM profiles) AS profiles
  `);
  res.json(rows[0]);
}));

// Sessions router (optional)
try {
  const sessionsRouter = require('./routes/sessions');
  app.use('/sessions', sessionsRouter);
} catch (e) {
  // ignore if not present
}

// Health + 404 + error handler
app.get('/ping', (req, res) => res.send('pong'));

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('ERROR', err && err.stack ? err.stack : err);
  res.status(500).json({ error: err.message || 'internal error' });
});
const db = require('./db'); // adjust path if needed

app.get('/_internal/db-check', async (req, res) => {
  try {
    const result = await db.query('SELECT NOW() as now');
    res.json({ ok: true, now: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});
// Start server
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});