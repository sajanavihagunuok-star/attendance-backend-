const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const {
  createAcademicYear,
  getAcademicYears,
  updateAcademicYear,
  deleteAcademicYear,
  createCourse,
  getCourses,
  updateCourse,
  deleteCourse,
  createBatch,
  getBatches,
  updateBatch,
  deleteBatch,
  createLecturer,
  deleteLecturer,
  getLecturers,
  createStudent,
  updateStudent,
  deleteStudent,
  getStudents,
  getAttendanceReport,
  updateProfile,
  resetPassword
} = require('../controllers/adminController');

// Middleware: Auth + Role check
router.use(verifyToken);
router.use(requireRole('admin'));

// Academic Years
router.post('/academic_years', createAcademicYear);
router.get('/academic_years', getAcademicYears);
router.put('/academic_years/:id', updateAcademicYear);
router.delete('/academic_years/:id', deleteAcademicYear);

// Courses
router.post('/courses', createCourse);
router.get('/courses', getCourses);
router.put('/courses/:id', updateCourse);
router.delete('/courses/:id', deleteCourse);

// Batches
router.post('/batches', createBatch);
router.get('/batches', getBatches);
router.put('/batches/:id', updateBatch);
router.delete('/batches/:id', deleteBatch);

// Lecturers
router.post('/lecturers', createLecturer);
router.get('/lecturers', getLecturers);
router.delete('/lecturers/:id', deleteLecturer);

// Students
router.post('/students', createStudent);
router.get('/students', getStudents);
router.put('/students/:id', updateStudent);
router.delete('/students/:id', deleteStudent);

// Attendance Reports
router.get('/attendance_report', getAttendanceReport);

// Profile + Password
router.put('/profile', updateProfile);
router.post('/reset_password', resetPassword);

module.exports = router;