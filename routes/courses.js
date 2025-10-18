const express = require('express');
const router = express.Router();

// In-memory example store for quick testing. Replace with DB calls.
let courses = [
  { id: 1, name: "Math 101", code: "MTH101" },
  { id: 2, name: "Intro CS", code: "CS100" }
];

router.get('/', (req, res) => {
  res.json(courses);
});

router.post('/', (req, res) => {
  const { name, code } = req.body;
  if (!name || !code) return res.status(400).json({ error: 'name and code required' });
  const id = courses.length ? Math.max(...courses.map(c => c.id)) + 1 : 1;
  const course = { id, name, code };
  courses.push(course);
  res.status(201).json(course);
});

module.exports = router;
