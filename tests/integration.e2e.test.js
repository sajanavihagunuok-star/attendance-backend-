// tests/integration.e2e.test.js
const request = require('supertest');

const API = 'http://127.0.0.1:3000';
const lecturerSub = '0e1e5c6c-b906-45dd-9edc-84b3838d8fbb';

// Provide a signed token via TEST_TOKEN env var when running tests.
// Example (PowerShell): $env:TEST_TOKEN = "eyJ..." ; npm run test:integration
const TOKEN = process.env.TEST_TOKEN || '';

function expectOk(res) {
  if (res.status >= 400) throw new Error(`Unexpected status ${res.status} ${JSON.stringify(res.body)}`);
}

describe('E2E: session → qr → profile → attendance → export', () => {
  let sessionId;
  let profileId;
  let qrPin;

  test('Create session (lecturer)', async () => {
    const payload = {
      course_id: process.env.TEST_COURSE_ID || '8df5b197-5ddd-4b92-aaf1-98ad451cc1e2',
      title: 'E2E Test Session',
      start_time: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      end_time: new Date(Date.now() + 65 * 60 * 1000).toISOString(),
      lecturer_id: lecturerSub
    };
    const req = request(API).post('/sessions').send(payload);
    if (TOKEN) req.set('Authorization', `Bearer ${TOKEN}`);
    const res = await req;
    expectOk(res);
    if (!res.body || !res.body.session) throw new Error('Missing session in response');
    sessionId = res.body.session.id;
  }, 10000);

  test('Generate QR / PIN', async () => {
    const req = request(API).post('/qr').send({ session_id: sessionId });
    if (TOKEN) req.set('Authorization', `Bearer ${TOKEN}`);
    const res = await req;
    expectOk(res);
    if (!res.body || !res.body.qr) throw new Error('Missing qr in response');
    qrPin = String(res.body.qr.pin);
    if (!/^\d{6}$/.test(qrPin)) throw new Error('PIN format invalid');
  }, 10000);

  test('Create test profile (student)', async () => {
    const res = await request(API).post('/profiles').send({ full_name: 'E2E Student' });
    expectOk(res);
    if (!res.body || !res.body.profile) throw new Error('Missing profile in response');
    profileId = res.body.profile.id;
  }, 10000);

  test('Mark attendance with PIN', async () => {
    const res = await request(API).post('/attendance').send({
      session_id: sessionId,
      student_id: profileId,
      attended: true,
      pin: qrPin
    });
    expectOk(res);
    if (!res.body || !res.body.attendance) throw new Error('Missing attendance in response');
    if (res.body.attendance.session_id !== sessionId) throw new Error('attendance.session_id mismatch');
  }, 10000);

  test('Export attendance CSV contains the created row', async () => {
    const res = await request(API)
      .get('/attendance/export')
      .query({ session_id: sessionId })
      .buffer()
      .parse((res, cb) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', chunk => data += chunk);
        res.on('end', () => cb(null, data));
      });
    expectOk(res);
    const text = res.body;
    if (typeof text !== 'string') throw new Error('Export response not string');
    if (!text.includes('attendance_id,session_id')) throw new Error('CSV header missing');
    if (!text.includes(sessionId)) throw new Error('CSV missing session id');
    if (!text.includes(profileId)) throw new Error('CSV missing profile id');
  }, 15000);

  test('Invalidate PIN (lecturer) cleans up', async () => {
    const req = request(API).post('/qr/invalidate').send({ session_id: sessionId });
    if (TOKEN) req.set('Authorization', `Bearer ${TOKEN}`);
    const res = await req;
    expectOk(res);
    if (typeof res.body.invalidated === 'undefined') throw new Error('Invalidate response missing invalidated count');
  });
});