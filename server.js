📄 FILE 2 — backend/server.js
██████████████████████████████████████████████████████████████████████
📝 The backend server. Save this inside a 'backend' folder as 'server.js'.
──────────────────────────────────────────────────────────────────────
javascript/* ════════════════════════════════════════════════════════
   THE FAME WALL — Backend (Express + SQLite + Resend email)
   Handles: register, real email verification code, sign in,
   resend code, session check.
   ════════════════════════════════════════════════════════ */

require('dotenv').config();

const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const rateLimit    = require('express-rate-limit');
const { Resend }   = require('resend');
const Database     = require('better-sqlite3');
const path         = require('path');
const crypto       = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Validate required env vars early ───────────────────────
const REQUIRED_ENV = ['RESEND_API_KEY', 'JWT_SECRET', 'FROM_EMAIL'];
const missing = REQUIRED_ENV.filter(k => !process.env[k] || process.env[k].includes('xxxx') || process.env[k].includes('replace_this'));
if (missing.length) {
  console.warn('⚠ Missing or placeholder env vars:', missing.join(', '));
  console.warn('  → Copy .env.example to .env and fill in real values before going live.');
}

const resend = new Resend(process.env.RESEND_API_KEY);
const CODE_EXPIRY_MS = (parseInt(process.env.CODE_EXPIRY_MINUTES) || 15) * 60 * 1000;

app.use(cors({ origin: process.env.SITE_URL || '*' }));
app.use(express.json());

// ── Database (SQLite file, zero setup) ─────────────────────
const db = new Database(path.join(__dirname, 'famewall.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0,
    verify_code   TEXT,
    code_expires  INTEGER,
    created_at    INTEGER NOT NULL
  );
`);

// ── Helpers ──────────────────────────────────────────────────
function genCode() {
  return String(crypto.randomInt(100000, 999999));
}
function genId() {
  return crypto.randomUUID();
}
function signToken(user) {
  return jwt.sign(
    { sub: user.id, name: user.name, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
}
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated.' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session.' });
  }
}

// ── Rate limiting on sensitive routes (anti spam / brute force) ─
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,
  message: { error: 'Too many attempts. Please try again later.' },
});
app.use(['/api/register', '/api/login', '/api/verify', '/api/resend-code'], authLimiter);

// ── Real email sending via Resend ───────────────────────────
async function sendVerificationEmail(to, name, code) {
  const html = `
  <div style="background:#050308;padding:48px 24px;font-family:Georgia,serif;">
    <div style="max-width:440px;margin:0 auto;background:#0d0a14;border:1px solid rgba(229,187,85,0.3);border-radius:12px;padding:40px 32px;text-align:center;">
      <div style="font-family:Georgia,serif;letter-spacing:0.3em;color:#E5BB55;font-size:13px;margin-bottom:8px;">✦ THE FAME WALL ✦</div>
      <h1 style="color:#F7F1E3;font-size:22px;margin:16px 0 8px;">Confirm your email</h1>
      <p style="color:#8a7f9a;font-size:14px;line-height:1.6;margin-bottom:28px;">
        Hi ${name ? escapeHtmlServer(name) : 'there'}, use the code below to verify your account and
        unlock access to The Fame Wall. This code expires in
        ${parseInt(process.env.CODE_EXPIRY_MINUTES) || 15} minutes.
      </p>
      <div style="display:inline-block;background:rgba(229,187,85,0.08);border:1px solid rgba(229,187,85,0.4);
                  border-radius:8px;padding:16px 32px;font-size:32px;letter-spacing:0.4em;color:#FCE8B0;font-family:monospace;margin-bottom:28px;">
        ${code}
      </div>
      <p style="color:#5c5468;font-size:12px;">If you didn't request this, you can safely ignore this email.</p>
    </div>
  </div>`;

  return resend.emails.send({
    from:    process.env.FROM_EMAIL,
    to,
    subject: `${code} — Your Fame Wall verification code`,
    html,
  });
}

function escapeHtmlServer(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ══════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════

// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields are required.' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'Invalid email address.' });

    const normEmail = email.trim().toLowerCase();
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normEmail);
    if (existing) return res.status(409).json({ error: 'An account with this email already exists.' });

    const id           = genId();
    const passwordHash = await bcrypt.hash(password, 10);
    const code          = genCode();
    const codeExpires   = Date.now() + CODE_EXPIRY_MS;

    db.prepare(`
      INSERT INTO users (id, name, email, password_hash, verified, verify_code, code_expires, created_at)
      VALUES (?, ?, ?, ?, 0, ?, ?, ?)
    `).run(id, name.trim(), normEmail, passwordHash, code, codeExpires, Date.now());

    try {
      await sendVerificationEmail(normEmail, name.trim(), code);
    } catch (emailErr) {
      console.error('Resend error:', emailErr);
      // Account exists in DB but email failed — let the client know so they can request a resend
      return res.status(201).json({
        ok: true,
        emailSent: false,
        warning: 'Account created, but the verification email could not be sent. Use "Resend code".',
      });
    }

    res.status(201).json({ ok: true, emailSent: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// POST /api/verify
app.post('/api/verify', (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: 'Email and code are required.' });

    const normEmail = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normEmail);
    if (!user) return res.status(404).json({ error: 'Account not found.' });
    if (user.verified) return res.status(400).json({ error: 'Account already verified.' });
    if (!user.verify_code || user.verify_code !== String(code).trim())
      return res.status(400).json({ error: 'Incorrect code.' });
    if (Date.now() > user.code_expires)
      return res.status(400).json({ error: 'Code expired. Please request a new one.' });

    db.prepare('UPDATE users SET verified = 1, verify_code = NULL, code_expires = NULL WHERE id = ?').run(user.id);

    const safeUser = { id: user.id, name: user.name, email: user.email };
    const token = signToken(safeUser);
    res.json({ ok: true, token, user: safeUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// POST /api/resend-code
app.post('/api/resend-code', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    const normEmail = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normEmail);
    if (!user) return res.status(404).json({ error: 'Account not found.' });
    if (user.verified) return res.status(400).json({ error: 'Account already verified.' });

    const code = genCode();
    const codeExpires = Date.now() + CODE_EXPIRY_MS;
    db.prepare('UPDATE users SET verify_code = ?, code_expires = ? WHERE id = ?').run(code, codeExpires, user.id);

    await sendVerificationEmail(normEmail, user.name, code);
    res.json({ ok: true, emailSent: true });
  } catch (err) {
    console.error('Resend error:', err);
    res.status(500).json({ error: 'Could not resend code. Please try again shortly.' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });

    const normEmail = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normEmail);
    if (!user) return res.status(401).json({ error: 'Incorrect email or password.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });

    if (!user.verified) {
      // Auto-send a fresh code so the client can jump straight to verification
      const code = genCode();
      const codeExpires = Date.now() + CODE_EXPIRY_MS;
      db.prepare('UPDATE users SET verify_code = ?, code_expires = ? WHERE id = ?').run(code, codeExpires, user.id);
      try { await sendVerificationEmail(normEmail, user.name, code); } catch (e) { console.error(e); }
      return res.status(403).json({ error: 'EMAIL_NOT_VERIFIED', email: normEmail });
    }

    const safeUser = { id: user.id, name: user.name, email: user.email };
    const token = signToken(safeUser);
    res.json({ ok: true, token, user: safeUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// GET /api/me  (validate an existing session token)
app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, name, email, verified FROM users WHERE id = ?').get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: { id: user.id, name: user.name, email: user.email } });
});

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`✦ The Fame Wall backend running on http://localhost:${PORT}`);
  console.log(`  Email sending via Resend ${process.env.RESEND_API_KEY?.includes('xxxx') ? '(⚠ NOT CONFIGURED YET)' : '(configured)'}`);
});

──────────────────────────────────────────────────────────────────────
END OF FILE: FILE 2 — backend/server.js
