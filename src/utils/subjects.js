// src/utils/subjects.js
// Admin-managed subject store. Each subject: { code, title, description, batch, year, createdAt }

const KEY = 'app_subjects_v1'

export function readSubjects() {
  try { return JSON.parse(localStorage.getItem(KEY) || '[]') } catch { return [] }
}
export function writeSubjects(list) {
  localStorage.setItem(KEY, JSON.stringify(list || []))
}
export function findByCode(code) {
  if (!code) return null
  const c = code.toString().trim().toLowerCase()
  return readSubjects().find(s => (s.code || '').toLowerCase() === c) || null
}
export function searchCodes(prefix) {
  const p = (prefix || '').toString().trim().toLowerCase()
  if (!p) return []
  return readSubjects().filter(s => (s.code || '').toLowerCase().startsWith(p)).slice(0, 20)
}
export function seedExample() {
  const existing = readSubjects()
  if (existing.length) return
  const demo = [
    { code: 'IT201', title: 'Introduction to IT', description: 'Basics of computing', batch: 'B1', year: '2025', createdAt: Date.now() },
    { code: 'CS101', title: 'Programming Fundamentals', description: 'Intro to programming', batch: 'B1', year: '2025', createdAt: Date.now() },
    { code: 'MA110', title: 'Calculus I', description: 'Basics of calculus', batch: 'B2', year: '2025', createdAt: Date.now() }
  ]
  writeSubjects(demo)
}
