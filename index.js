// Force IPv4-first DNS resolution immediately
require("dns").setDefaultResultOrder("ipv4first");
// allow TLS for managed certs while debugging
process.env.NODE_TLS_REJECT_UNAUTHORIZED = process.env.NODE_TLS_REJECT_UNAUTHORIZED || "0";
// Force IPv4-first DNS resolution immediately
require('dns').setDefaultResultOrder('ipv4first');
// allow self-signed/managed certs for TLS if your environment needs it (only while debugging)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = process.env.NODE_TLS_REJECT_UNAUTHORIZED || '0';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { randomUUID } = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const asyncHandler = require('express-async-handler');
const { verifyToken, requireAuth, requireRole } = require('./middleware/auth');

const app = express();
// TEMP resilient raw-body sanitizer — keep before express.json()
app.use((req, res, next) => {
  // only run for requests that may have a body
  if (!['POST','PUT','PATCH','DELETE'].includes((req.method || '').toUpperCase())) return next();

  const chunks = [];
  let received = 0;
  req.on('data', (c) => {
    const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
    chunks.push(buf);
    received += buf.length;
    // safety bail for enormous bodies
    if (received > 2 * 1024 * 1024) { // 2MB
      console.error('BODY-SANITIZER: body too large');
      req.destroy();
    }
  });

  req.on('end', () => {
    try {
      const buf = Buffer.concat(chunks || []);
      // strip UTF-8 BOM if present
      let start = 0;
      if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) start = 3;
      // if request accidentally contains garbage before JSON, find first { or [
      const firstBrace = buf.slice(start).indexOf(0x7b); // '{'
      const firstBracket = buf.slice(start).indexOf(0x5b); // '['
      let firstJson = -1;
      if (firstBrace >= 0 && firstBracket >= 0) firstJson = Math.min(firstBrace, firstBracket);
      else firstJson = Math.max(firstBrace, firstBracket);
      if (firstJson >= 0) start = start + firstJson;
      const cleanBuf = buf.slice(start);
      // optional debug (short preview) - remove after fix
      console.log('BODY-SANITIZER: len', buf.length, 'cleanLen', cleanBuf.length, 'preview', cleanBuf.slice(0,120).toString());
      // create a new readable stream for downstream parsers
      const { Readable } = require('stream');
      const s = new Readable();
      s.push(cleanBuf);
      s.push(null);
      // copy minimal properties expected by body-parser
      s.headers = req.headers;
      s.method = req.method;
      s.url = req.url;
      // replace req's internal stream methods so express body-parser can read from it
      req.socket = req.socket || s;
      req._read = s._read?.bind(s);
      req.read = s.read?.bind(s);
      req.on = s.on?.bind(s);
      req.pipe = s.pipe?.bind(s);
      // attach the cleaned raw string for diagnostic access if needed
      req._rawSanitized = cleanBuf.toString('utf8');
      next();
    } catch (err) {
      console.error('BODY-SANITIZER-ERROR', err);
      // allow upstream to handle parse error normally
      next();
    }
  });

  req.on('error', (e) => { console.error('BODY-SANITIZER-STREAM-ERR', e); next(); });
});
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in .env');
  process.exit(1);
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
// DEBUG: dump raw request body as hex for troubleshooting malformed JSON
const http = require('http');
if (!global.__RAW_BODY_LOGGER_ADDED) {
  global.__RAW_BODY_LOGGER_ADDED = true;
  const express = require('express');
  const original = express.request;
  // attach rawBody logger middleware insertion helper for earliest position
  // the code below registers a middleware that buffers raw bytes then sets req.rawBodyHex
  module.exports = (function() {
    try {
      const appRef = require('./index'); // safe no-op when index requires itself; ignore errors
    } catch(e) { /* ignore */ }
  })();
}
process.on('uncaughtException', (err) => { console.error('UNCAUGHT', err && err.stack || err); });
app.use(cors());
app.use(express.json());
app.use(verifyToken);
app.use(express.urlencoded({ extended: true }));
app.get('/ping', (req, res) => res.send('pong'));

// ---------- RATE LIMITERS ----------
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

// ---------- HELPERS ----------
const isUuid = s => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const hash = async (pw) => await bcrypt.hash(pw, 10);
const verify = async (pw, h) => await bcrypt.compare(pw, h);

function signToken(payload) {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return jwt.sign(payload, secret, { expiresIn: '12h' });
}
function requireInstitute(req, res, next) {
  const iid = req.user && req.user.institute_id;
  if (!iid && !req.body.institute_id && !req.query.institute_id) {
    return res.status(403).json({ error: 'Institute scope required' });
  }
  req.institute_id = req.user.institute_id || req.body.institute_id || req.query.institute_id;
  next();
}

async function audit(actorUserId, action, entityType, entityId, payload) {
  await pool.query(
    'INSERT INTO audits(actor_user_id, action, entity_type, entity_id, payload) VALUES ($1,$2,$3,$4,$5)',
    [actorUserId, action, entityType, entityId, payload || {}]
  );
}

// ---------- AUTH / USER / INSTITUTE ----------
app.post('/institutes', asyncHandler(async (req, res) => {
  const { name, domain } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const { rows } = await pool.query(
    'INSERT INTO institutes(id,name,domain,created_at) VALUES (gen_random_uuid(), $1, $2, now()) RETURNING *',
    [name, domain || null]
  );
  res.json({ institute: rows[0] });
}));

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
      await client.query(
        'INSERT INTO profiles(user_id,full_name,created_at) VALUES ($1,$2,now())',
        [user.id, full_name]
      );
    }
    await audit(user.id, 'register', 'user', user.id, { email, institute_id, role });
    await client.query('COMMIT');
    const token = signToken({
      sub: user.id,
      role: user.role,
      email: user.email,
      institute_id: user.institute_id
    });
    res.json({ user, token });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'user exists' });
    throw err;
  } finally {
    client.release();
  }
}));

app.post('/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email.toLowerCase()]);
  if (!rows[0]) return res.status(401).json({ error: 'Invalid credentials' });
  const user = rows[0];
  if (!user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await verify(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = signToken({
    sub: user.id,
    role: user.role,
    email: user.email,
    institute_id: user.institute_id
  });
  await audit(user.id, 'login', 'user', user.id, {});
  res.json({
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
      institute_id: user.institute_id
    },
    token
  });
}));
// ---------- COURSES ----------
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
  const institute_id = req.query.institute_id || req.user && req.user.institute_id;
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

  const { rows } = await pool.query(
    'UPDATE courses SET name=$1, description=$2, code=$3, updated_at=now() WHERE id=$4 RETURNING *',
    [name, description || null, code, id]
  );
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

// ---------- BATCHES ----------
app.post('/batches', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });

  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });

  const { rows } = await pool.query(
    'INSERT INTO batches(id,institute_id,name,created_at) VALUES (gen_random_uuid(), $1, $2, now()) RETURNING *',
    [actorRow.institute_id, name]
  );
  await audit(actor.sub, 'create_batch', 'batch', rows[0].id, { name });
  res.json({ batch: rows[0] });
}));

app.get('/batches', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await pool.query('SELECT * FROM batches WHERE institute_id = $1 ORDER BY created_at DESC', [inst]);
  res.json({ batches: rows });
}));

// ---------- ENROLLMENTS ----------
app.post('/enrollments', requireAuth, asyncHandler(async (req, res) => {
  const actor = req.auth;
  const actorRow = (await pool.query('SELECT * FROM users WHERE id=$1 LIMIT 1', [actor.sub])).rows[0];
  if (!(actorRow && ['owner','super_admin','admin'].includes(actorRow.role))) return res.status(403).json({ error: 'Admin required' });

  const { student_id, course_id, batch_id } = req.body || {};
  if (!student_id || !course_id) return res.status(400).json({ error: 'student_id and course_id required' });

  const { rows } = await pool.query(
    'INSERT INTO enrollments(id,student_id,course_id,batch_id,created_at) VALUES (gen_random_uuid(), $1, $2, $3, now()) RETURNING *',
    [student_id, course_id, batch_id || null]
  );
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

// ---------- PROFILES ----------
app.get('/profiles', requireAuth, asyncHandler(async (req, res) => {
  const inst = req.user && req.user.institute_id;
  const { rows } = await pool.query(
    'SELECT * FROM profiles WHERE (user_id IS NULL OR user_id IN (SELECT id FROM users WHERE institute_id = $1)) ORDER BY created_at DESC LIMIT 1000',
    [inst]
  );
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
// ---------- SESSIONS ----------
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

// ---------- QR / PIN ----------
app.post('/qr', qrRateLimiter, asyncHandler(async (req, res) => {
  const { session_id } = req.body || {};
  if (!session_id) return res.status(400).json({ error: 'session_id required' });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });

  const { rows: srows } = await pool.query(
    'SELECT id, course_id, lecturer_id, start_time FROM sessions WHERE id = $1 LIMIT 1',
    [session_id]
  );
  if (!srows[0]) return res.status(404).json({ error: 'Session not found' });
  const sess = srows[0];
  if (!sess.course_id || !sess.lecturer_id || !sess.start_time) {
    return res.status(400).json({ error: 'Session missing required details. Fill course, lecturer and start_time before generating QR.' });
  }

  const existing = (await pool.query(
    'SELECT * FROM session_qr WHERE session_id=$1 AND expires_at >= now() ORDER BY created_at DESC LIMIT 1',
    [session_id]
  )).rows[0];
  if (existing) {
    return res.json({ qr: existing, note: 'existing_active' });
  }

  const pin = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  const q = `INSERT INTO session_qr(session_id, pin, expires_at) VALUES ($1, $2, $3) RETURNING *`;
  const { rows } = await pool.query(q, [session_id, pin, expiresAt]);
  res.json({ qr: { session_id, pin: rows[0].pin, expires_at: rows[0].expires_at, created_at: rows[0].created_at } });
}));

app.get('/qr/:session_id', asyncHandler(async (req, res) => {
  const session_id = req.params.session_id;
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  const { rows } = await pool.query(
    'SELECT * FROM session_qr WHERE session_id = $1 AND expires_at >= now() ORDER BY created_at DESC LIMIT 1',
    [session_id]
  );
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
// ---------- ATTENDANCE ----------
app.post('/attendance', asyncHandler(async (req, res) => {
  const { session_id, student_id, attended, pin } = req.body || {};
  if (!session_id || !student_id) return res.status(400).json({ error: 'Missing fields', missing: ['session_id','student_id'] });
  if (!isUuid(session_id)) return res.status(400).json({ error: 'invalid session_id' });
  if (!isUuid(student_id)) return res.status(400).json({ error: 'invalid student_id' });

  const isAdminOrLecturer = req.user && ['admin','lecturer','super_admin','owner'].includes(req.user.role);
  if (!isAdminOrLecturer) {
    if (!pin) return res.status(403).json({ error: 'PIN required for marking attendance' });
    const { rows: pinRows } = await pool.query(
      'SELECT * FROM session_qr WHERE session_id = $1 AND pin = $2 ORDER BY created_at DESC LIMIT 1',
      [session_id, String(pin)]
    );
    if (!pinRows[0]) return res.status(403).json({ error: 'Invalid PIN' });
    if (new Date(pinRows[0].expires_at) < new Date()) return res.status(403).json({ error: 'PIN expired' });
  }

  const q = `INSERT INTO attendance(id, session_id, student_id, attended, marked_at)
             VALUES (gen_random_uuid(), $1, $2, $3, now()) RETURNING *`;
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

// ---------- DEBUG ----------
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

const sessionsRouter = require('./routes/sessions');
app.use('/sessions', sessionsRouter);

// ---------- HEALTH + ERROR + 404 ----------
app.get('/ping', (req, res) => res.send('pong'));

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('ERROR', err && err.stack ? err.stack : err);
  res.status(500).json({ error: err.message || 'internal error' });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});


