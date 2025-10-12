import jwt from 'jsonwebtoken'
const payload = { id: 'admin', email: 'mentorbridge.lk@gmail.com', role: 'admin' }
const token = jwt.sign(payload, process.env.JWT_SECRET || 'testsecret', { expiresIn: '7d' })
console.log(token)
