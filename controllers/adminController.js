// backend/controllers/adminController.js
const db = require('../db'); // adjust if your DB connection file is named differently
const { v4: uuidv4 } = require('uuid');

/* Simple logger */
const log = {
  info: (...args) => {
    if (process.env.NODE_ENV !== 'test') console.info('[adminController][INFO]', ...args);
  },
  error: (...args) => {
    console.error('[adminController][ERROR]', ...args);
  }
};

/* Helpers */
function safeFilterQuery(filter) {
  if (!filter || typeof filter !== 'object') return { sql: '', params: [] };
  const allowedKeys = ['student_id', 'batch_id', 'course_id', 'institute_id'];
  const key = filter.key;
  const value = filter.value;
  if (!allowedKeys.includes(key)) return { sql: '', params: [] };
  return { sql: `WHERE ${key} = $1`, params: [value] };
}

function buildUpdateQuery(table, idField, id, fields) {
  const updates = [];
  const params = [];
  let idx = 1;
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    updates.push(`${k}=$${idx++}`);
    params.push(v);
  }
  if (!updates.length) return null;
  params.push(id);
  return {
    sql: `UPDATE ${table} SET ${updates.join(', ')} WHERE ${idField}=$${idx}`,
    params
  };
}

/* Academic Years */
exports.createAcademicYear = async (req, res) => {
  const { name, start_date, end_date, institute_id } = req.body;
  if (!name || !start_date || !end_date || !institute_id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await db.query(
      `INSERT INTO academic_years (id, name, start_date, end_date, institute_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [uuidv4(), name, start_date, end_date, institute_id]
    );
    log.info('Created academic year', { name, institute_id });
    res.json({ success: true });
  } catch (err) {
    log.error('createAcademicYear failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.getAcademicYears = async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM academic_years`);
    res.json(result.rows);
  } catch (err) {
    log.error('getAcademicYears failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.updateAcademicYear = async (req, res) => {
  const { id } = req.params;
  const { name, start_date, end_date } = req.body;
  if (!id || !name || !start_date || !end_date) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await db.query(
      `UPDATE academic_years SET name=$1, start_date=$2, end_date=$3 WHERE id=$4`,
      [name, start_date, end_date, id]
    );
    log.info('Updated academic year', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('updateAcademicYear failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.deleteAcademicYear = async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await db.query(`DELETE FROM academic_years WHERE id=$1`, [id]);
    log.info('Deleted academic year', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('deleteAcademicYear failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

/* Courses */
exports.createCourse = async (req, res) => {
  const { name, description, institute_id } = req.body;
  if (!name || !institute_id) return res.status(400).json({ error: 'Missing required fields' });
  try {
    await db.query(
      `INSERT INTO courses (id, name, description, institute_id)
       VALUES ($1, $2, $3, $4)`,
      [uuidv4(), name, description || null, institute_id]
    );
    log.info('Created course', { name, institute_id });
    res.json({ success: true });
  } catch (err) {
    log.error('createCourse failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.getCourses = async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM courses`);
    res.json(result.rows);
  } catch (err) {
    log.error('getCourses failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.updateCourse = async (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'Missing required fields' });
  try {
    await db.query(
      `UPDATE courses SET name=$1, description=$2 WHERE id=$3`,
      [name, description || null, id]
    );
    log.info('Updated course', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('updateCourse failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.deleteCourse = async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await db.query(`DELETE FROM courses WHERE id=$1`, [id]);
    log.info('Deleted course', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('deleteCourse failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

/* Batches */
exports.createBatch = async (req, res) => {
  const { name, course_id } = req.body;
  if (!name || !course_id) return res.status(400).json({ error: 'Missing required fields' });
  try {
    await db.query(
      `INSERT INTO batches (id, name, course_id)
       VALUES ($1, $2, $3)`,
      [uuidv4(), name, course_id]
    );
    log.info('Created batch', { name, course_id });
    res.json({ success: true });
  } catch (err) {
    log.error('createBatch failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.getBatches = async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM batches`);
    res.json(result.rows);
  } catch (err) {
    log.error('getBatches failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.updateBatch = async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'Missing required fields' });
  try {
    await db.query(`UPDATE batches SET name=$1 WHERE id=$2`, [name, id]);
    log.info('Updated batch', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('updateBatch failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.deleteBatch = async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await db.query(`DELETE FROM batches WHERE id=$1`, [id]);
    log.info('Deleted batch', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('deleteBatch failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

/* Lecturers */
exports.createLecturer = async (req, res) => {
  const { name, email, institute_id } = req.body;
  if (!name || !email || !institute_id) return res.status(400).json({ error: 'Missing required fields' });
  try {
    await db.query(
      `INSERT INTO users (id, name, email, role, institute_id)
       VALUES ($1, $2, $3, 'lecturer', $4)`,
      [uuidv4(), name, email, institute_id]
    );
    log.info('Created lecturer', { email, institute_id });
    res.json({ success: true });
  } catch (err) {
    log.error('createLecturer failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.getLecturers = async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM users WHERE role='lecturer'`);
    res.json(result.rows);
  } catch (err) {
    log.error('getLecturers failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.deleteLecturer = async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await db.query(`DELETE FROM users WHERE id=$1 AND role='lecturer'`, [id]);
    log.info('Deleted lecturer', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('deleteLecturer failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

/* Students with transaction for create + optional enrollment */


exports.createStudent = async (req, res) => {
  const { name, email, institute_id, academic_year_id, batch_id } = req.body;
  if (!name || !email || !institute_id || !academic_year_id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // DNS-safe guard: if DB is unreachable, return 502
  if (db.query && typeof db.query === 'function') {
    try {
      await db.query('SELECT 1'); // triggers DNS resolution
    } catch (err) {
      if (err.code === 'DB_UNREACHABLE' || err.message.includes('ENOTFOUND')) {
        return res.status(502).json({ error: 'Database unreachable. Try again later.' });
      }
    }
  }

try { await db.query('SELECT 1'); } catch (err) {
  if (err.code === 'DB_UNREACHABLE' || err.message.includes('ENOTFOUND')) return res.status(502).json({ error: 'Database unreachable. Try again later.' });
  throw err;
}
const client = await db.connect();
  try {
    await client.query('BEGIN');

    const userId = uuidv4();
    await client.query(
      `INSERT INTO users (id, name, email, role, institute_id, academic_year_id)
       VALUES ($1, $2, $3, 'student', $4, $5)`,
      [userId, name, email, institute_id, academic_year_id]
    );

    if (batch_id) {
      const enrollmentId = uuidv4();
      await client.query(
        `INSERT INTO enrollments (id, student_id, batch_id, institute_id)
         VALUES ($1, $2, $3, $4)`,
        [enrollmentId, userId, batch_id, institute_id]
      );
      console.info('Created student and enrollment', { userId, batch_id });
    } else {
      console.info('Created student', { userId });
    }

    await client.query('COMMIT');
    res.status(201).json({ success: true, id: userId });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('createStudent transaction failed', err.message);
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
};

exports.getStudents = async (req, res) => {
  try {
    const result = await db.query(`SELECT * FROM users WHERE role='student'`);
    res.json(result.rows);
  } catch (err) {
    log.error('getStudents failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.updateStudent = async (req, res) => {
  const { id } = req.params;
  const { name, email } = req.body;
  if (!id || (!name && !email)) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const updates = [];
    const params = [];
    let idx = 1;
    if (name) { updates.push(`name=$${idx++}`); params.push(name); }
    if (email) { updates.push(`email=$${idx++}`); params.push(email); }
    params.push(id);
    await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id=$${idx} AND role='student'`, params);
    log.info('Updated student', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('updateStudent failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.deleteStudent = async (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  try {
    await db.query(`DELETE FROM users WHERE id=$1 AND role='student'`, [id]);
    log.info('Deleted student', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('deleteStudent failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

/* Attendance Reports */
exports.getAttendanceReport = async (req, res) => {
  const { filter } = req.query; // expecting JSON: ?filter={"key":"student_id","value":"..."}
  let parsed;
  try {
    parsed = typeof filter === 'string' ? JSON.parse(filter) : filter;
  } catch (e) {
    return res.status(400).json({ error: 'Invalid filter format' });
  }
  const { sql, params } = safeFilterQuery(parsed);
  if (!sql) return res.status(400).json({ error: 'Invalid or missing filter' });
  try {
    const result = await db.query(`SELECT * FROM attendance ${sql}`, params);
    res.json(result.rows);
  } catch (err) {
    log.error('getAttendanceReport failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

/* Profile + Password */
exports.updateProfile = async (req, res) => {
  const { id, name, email } = req.body;
  if (!id || (!name && !email)) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const updates = [];
    const params = [];
    let idx = 1;
    if (name) { updates.push(`name=$${idx++}`); params.push(name); }
    if (email) { updates.push(`email=$${idx++}`); params.push(email); }
    params.push(id);
    await db.query(`UPDATE users SET ${updates.join(', ')} WHERE id=$${idx}`, params);
    log.info('Updated profile', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('updateProfile failed', err.message);
    res.status(500).json({ error: err.message });
  }
};

exports.resetPassword = async (req, res) => {
  const { id, new_password } = req.body;
  if (!id || !new_password) return res.status(400).json({ error: 'Missing required fields' });
  try {
    // In production hash this value
    await db.query(`UPDATE users SET password=$1 WHERE id=$2`, [new_password, id]);
    log.info('Password reset', { id });
    res.json({ success: true });
  } catch (err) {
    log.error('resetPassword failed', err.message);
    res.status(500).json({ error: err.message });
  }
};