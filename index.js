// Force IPv4-first DNS resolution immediately
require('dns').setDefaultResultOrder('ipv4first');
// Allow TLS for managed certs while debugging; remove or tighten for production
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

// ---------- SAFE raw JSON sanitize helper (used in express.json verify) ----------
function sanitizeRawBuffer(buf) {
  if (!buf || !buf.length) return buf;
  // strip UTF-8 BOM if present
  let start = 0;
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) start = 3;
  // find first JSON starting char '{' or '['
  const rest = buf.slice(start);
  const iBrace = rest.indexOf(0x7b); // '{'
  const iBracket = rest.indexOf(0x5b); // '['
  let i = -1;
  if (iBrace >= 0 && iBracket >= 0) i = Math.min(iBrace, iBracket);
  else i = Math.max(iBrace, iBracket);
  if (i >= 0) start = start + i;
  return buf.slice(start);
}

// ---------- middlewares ----------
app.use(cors());
app.use(express.json({
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      // TEMP logging for debugging malformed JSON - remove after fix
      const hex = Buffer.from(buf).toString('hex');
      const text = Buffer.from(buf).toString('utf8');
      console.log('RAW-INCOMING-HEX', hex);
      console.log('RAW-INCOMING-TEXT', text);
      req._rawSanitized = sanitizeRawBuffer(buf).toString('utf8');
    } catch (err) {
      console.error('RAW-VERIFY-ERR', err);
    }
  }
}));
app.use(express.urlencoded({ extended: false }));
app.use(verifyToken);

// ---------- config ----------
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in .env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('postgres') ? { rejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0' } : false
});

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

// (file continues unchanged)