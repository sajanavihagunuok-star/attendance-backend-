// index.js
// Minimal backend single-file replacement. ES module (Node >= 18/20/22).
// Features:
// - Demo auth register/login with JWT signed by JWT_SECRET (default "change_this_for_prod")
// - Local JSON persistence (data.json) for sessions and attendance
// - Endpoints used in your workflows: /auth/register, /auth/login, /sessions, /sessions/:id/attendance
// - Simple role field on users; created token payload: { id, email, role }

import express from "express";
import fs from "fs";
import path from "path";
import { randomUUID } from "crypto";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";

const app = express();
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_for_prod";
const DATA_FILE = path.resolve("./data.json");

// --- Load / save store
let store = { users: [], sessions: [], attendance: [], exportedAt: Date.now() };

function loadStore() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, "utf8") || "{}";
      const parsed = JSON.parse(raw);
      store.users = Array.isArray(parsed.users) ? parsed.users : [];
      store.sessions = Array.isArray(parsed.sessions) ? parsed.sessions : [];
      store.attendance = Array.isArray(parsed.attendance) ? parsed.attendance : [];
      store.exportedAt = parsed.exportedAt || Date.now();
    } else {
      saveStore();
    }
  } catch (e) {
    console.error("loadStore error", e);
    store = { users: [], sessions: [], attendance: [], exportedAt: Date.now() };
    saveStore();
  }
}

function saveStore() {
  try {
    store.exportedAt = Date.now();
    fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2));
  } catch (e) {
    console.error("saveStore error", e);
  }
}

loadStore();

// --- Helpers
function signToken(payload) {
  // 30 days default expiry (matches your previous tokens)
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    throw e;
  }
}

// --- DB helper functions using local store
async function createUser({ email, password, displayName, role = "student" }) {
  const existing = store.users.find((u) => u.email === email);
  if (existing) return null;
  const user = {
    id: randomUUID(),
    email,
    password: password || null, // plain text for demo only
    displayName: displayName || email,
    role,
    createdAt: new Date().toISOString(),
  };
  store.users.push(user);
  saveStore();
  return user;
}

async function findUserByEmail(email) {
  return store.users.find((u) => u.email === email) || null;
}

async function createSessionDb({ subjectId, start, end, createdBy }) {
  const s = {
    id: randomUUID(),
    subjectId,
    start: start || null,
    end: end || null,
    createdBy: createdBy || null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  store.sessions.push(s);
  saveStore();
  return s;
}

async function listSessionsDb() {
  return store.sessions.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

async function getAttendanceDb(sessionId) {
  return (store.attendance || []).filter((r) => r.sessionId === sessionId).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

async function createAttendanceDb({ sessionId, userId, present = true }) {
  const rec = {
    id: randomUUID(),
    sessionId,
    userId,
    present,
    timestamp: new Date().toISOString(),
  };
  store.attendance = Array.isArray(store.attendance) ? store.attendance : [];
  store.attendance.push(rec);
  saveStore();
  return rec;
}

// --- Auth endpoints
app.post("/auth/register", async (req, res) => {
  const { email, password, displayName, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });
  const user = await createUser({ email, password, displayName, role });
  if (!user) return res.status(409).json({ error: "User already exists" });
  const token = signToken({ id: user.id, email: user.email, role: user.role });
  return res.json({ user: { id: user.id, email: user.email, displayName: user.displayName, role: user.role }, token });
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email or password" });
  const user = await findUserByEmail(email);
  if (!user || user.password !== password) return res.status(401).json({ error: "Invalid credentials" });
  const token = signToken({ id: user.id, email: user.email, role: user.role });
  return res.json({ user: { id: user.id, email: user.email, displayName: user.displayName, role: user.role }, token });
});

// --- Auth middleware
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  if (!header.startsWith("Bearer ")) return res.status(401).json({ error: "Missing authorization" });
  const token = header.slice("Bearer ".length);
  try {
    const payload = verifyToken(token);
    req.user = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- Routes: sessions
app.get("/sessions", authMiddleware, async (req, res) => {
  try {
    const sessions = await listSessionsDb();
    // normalize to older API shape (subjectId, createdBy, timestamps)
    return res.json(sessions.map((s) => ({
      id: s.id,
      subjectId: s.subjectId,
      start: s.start,
      end: s.end,
      createdBy: s.createdBy,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
    })));
  } catch (e) {
    console.error("list sessions error", e);
    return res.status(500).json({ error: "Failed to list sessions" });
  }
});

app.post("/sessions", authMiddleware, async (req, res) => {
  const { subjectId, start, end } = req.body || {};
  if (!subjectId || !start) return res.status(400).json({ error: "Missing subjectId or start" });
  try {
    const s = await createSessionDb({ subjectId, start, end, createdBy: req.user.id });
    return res.json({
      id: s.id,
      subjectId: s.subjectId,
      start: s.start,
      end: s.end,
      createdBy: s.createdBy,
      createdAt: s.createdAt,
      updatedAt: s.updatedAt,
    });
  } catch (e) {
    console.error("create session error", e);
    return res.status(500).json({ error: "Failed to create session" });
  }
});

// --- Routes: attendance
app.get("/sessions/:id/attendance", authMiddleware, async (req, res) => {
  const sessionId = req.params.id;
  try {
    const rows = await getAttendanceDb(sessionId);
    return res.json(rows);
  } catch (e) {
    console.error("get attendance error", e);
    return res.status(500).json({ error: "Failed to get attendance" });
  }
});

app.post("/sessions/:id/attendance", authMiddleware, async (req, res) => {
  const sessionId = req.params.id;
  // if userId provided and caller is instructor, allow marking for others
  const { userId } = req.body || {};
  try {
    const callerId = req.user && req.user.id;
    let targetUserId = callerId;
    // instructor can mark for others
    if (userId && req.user && req.user.role === "instructor") {
      targetUserId = userId;
    }
    // verify session exists
    const exists = store.sessions.find((s) => s.id === sessionId);
    if (!exists) return res.status(404).json({ error: "Session not found" });

    const rec = await createAttendanceDb({ sessionId, userId: targetUserId, present: true });
    return res.json(rec);
  } catch (e) {
    console.error("create attendance error", e);
    return res.status(500).json({ error: "Failed to mark attendance" });
  }
});

// --- Health
app.get("/health", (req, res) => res.json({ ok: true, env: { jwtSecret: !!process.env.JWT_SECRET } }));

// --- Start server
app.listen(PORT, () => {
  console.log(`Server listening at http://localhost:${PORT}`);
  console.log(`API listening on port ${PORT}`);
});
