// IPv4-first DNS optional (enable by setting DEBUG_IPV4=1)
if (process.env.DEBUG_IPV4 === '1') require('dns').setDefaultResultOrder('ipv4first');

// Allow disabling strict TLS checks only when explicitly requested (debug only)
if (process.env.DEBUG_TLS === '1') {
  console.warn('DEBUG_TLS is enabled. TLS certificate verification is disabled.');
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const { randomUUID } = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const asyncHandler = require('express-async-handler');

// Local auth middleware import (must exist)
const { verifyToken, requireAuth, requireRole } = require('./middleware/auth');

const app = express();

// ---------- Helpers ----------
function sanitizeRawBuffer(buf) {
  if (!buf || !buf.length) return buf;
  // strip UTF-8 BOM
  let start = 0;
  if (buf.length >= 3 && buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) start = 3;
  // find first JSON start char '{' or '['
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

// ---------- Middleware: JSON parse with verify that captures raw */
app.use(cors());
app.use(express.json({
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      req._rawSanitized = sanitizeRawBuffer(buf).toString('utf8');
      // Optional debug logging: enable DEBUG_RAW=1 in env to log raw text/hex
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

// ---------- Config ----------
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('Missing DATABASE_URL in environment');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.startsWith('postgres') ? { rejectUnauthorized: process.env.DEBUG_TLS !== '1' } : false
});

// ---------- Rate limiters ----------
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

// ---------- Helpers continued ----------
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

// ---------- Emergency fallback parser (disabled by default) ----------
// This tries to recover simple unquoted-key payloads like {email:foo,password:bar}
// Enable only temporarily by setting ALLOW_MALFORMED_JSON=1 in environment.
if (process.env.ALLOW_MALFORMED_JSON === '1') {
  app.use((req, res, next) => {
    if (!req.headers['content-type'] || !req.headers['content-type'].includes('application/json')) return next();
    if (req.body && Object.keys(req.body).length) return next();
    const raw = (req._rawSanitized || '').trim();
    if (!raw) return next();
    try {
      req.body = JSON.parse(raw);
      return next();
    } catch (e) {
      try {
        let t = raw;
        if (t[0] !== '{' && t[0] !== '[') t = '{' + t + '}';
        t = t.replace(/([{,]\s*)([a-zA-Z0-9_@\-\.]+)\s*:/g, '$1"$2":');
        t = t.replace(/:\s*([A-Za-z0-9@_\-+\/.:]+)(\s*[,\}])/g, (m, val, tail) => {
          if (/^(true|false|null|\d+(\.\d+)?)$/i.test(val)) return ':' + val + tail;
          if (val[0] === '"' || val[0] === "'") return ':' + val + tail;
          const escaped = String(val).replace(/"/g, '\\"');
          return ':"' + escaped + '"' + tail;
        });
        req.body = JSON.parse(t);
        req._forcedParsed = true;
        return next();
      } catch (ee) {
        console.error('FALLBACK-PARSE-ERR', ee && ee.stack || ee);
        return next();
      }
    }
  });
}

// ---------- Routes (complete) ----------

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
  const ok = await verify(password, user.password_hash);
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

// Batches, Enrollments, Profiles, Sessions, QR, Attendance, Export, Debug and other routes
// (copy the rest of your existing route implementations here exactly as you had them)
// For brevity the full route implementations are unchanged from your original file.
// Ensure the rest of your route handlers (sessions router, debug routes, exports) are pasted below.

const sessionsRouter = require('./routes/sessions');
app.use('/sessions', sessionsRouter);

// Health, 404, error handler
app.get('/ping', (req, res) => res.send('pong'));

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('ERROR', err && err.stack ? err.stack : err);
  res.status(500).json({ error: err.message || 'internal error' });
});

// Start
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});