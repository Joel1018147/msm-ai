/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║     M-SM AI — Production Server with Google OAuth       ║
 * ║     100% FREE — Groq AI + SQLite + JWT + Google Login   ║
 * ╚══════════════════════════════════════════════════════════╝
 *
 * SETUP:
 *   1. npm install
 *   2. Fill in .env (see .env.example)
 *   3. node server.js
 *
 * GOOGLE OAUTH SETUP:
 *   1. Go to console.cloud.google.com
 *   2. New Project → APIs & Services → Credentials
 *   3. Create OAuth 2.0 Client ID (Web application)
 *   4. Add Authorized redirect URIs:
 *      - http://localhost:3000/api/auth/google/callback  (local)
 *      - https://YOUR-APP.up.railway.app/api/auth/google/callback  (production)
 *   5. Copy Client ID and Client Secret to .env
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const Database  = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET     = process.env.JWT_SECRET || 'msm-ai-dev-secret-change-in-production';
const GROQ_KEY       = process.env.GROQ_API_KEY;
const GOOGLE_ID      = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET  = process.env.GOOGLE_CLIENT_SECRET;
const APP_URL        = process.env.APP_URL || `http://localhost:${PORT}`;

// ════════════════════════════════════════════════════
//  DATABASE
// ════════════════════════════════════════════════════
const db = new Database(process.env.DB_PATH || './msm-ai.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT UNIQUE NOT NULL,
    password      TEXT,
    google_id     TEXT UNIQUE,
    avatar        TEXT,
    plan          TEXT DEFAULT 'free',
    credits       INTEGER DEFAULT 2500,
    credits_max   INTEGER DEFAULT 2500,
    groq_key      TEXT,
    brand_name    TEXT,
    brand_desc    TEXT,
    brand_tone    TEXT DEFAULT 'Professional',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME,
    is_active     INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS documents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    title       TEXT NOT NULL,
    content     TEXT,
    tool_id     TEXT,
    tool_name   TEXT,
    word_count  INTEGER DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS usage_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    action       TEXT NOT NULL,
    credits_used INTEGER DEFAULT 0,
    tool_id      TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

console.log('✓ Database ready');

// ════════════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many attempts. Try again in 15 minutes.' } });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests. Slow down.' } });

// ════════════════════════════════════════════════════
//  AUTH HELPERS
// ════════════════════════════════════════════════════
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Please log in to continue' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ? AND is_active = 1').get(decoded.userId);
    if (!user) return res.status(401).json({ error: 'Account not found' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

function makeToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

function safeUser(u) {
  return { id: u.id, name: u.name, email: u.email, plan: u.plan, credits: u.credits, credits_max: u.credits_max, avatar: u.avatar };
}

function spendCredits(userId, amount, toolId = null) {
  db.prepare('UPDATE users SET credits = MAX(0, credits - ?) WHERE id = ?').run(amount, userId);
  db.prepare('INSERT INTO usage_log (user_id, action, credits_used, tool_id) VALUES (?, ?, ?, ?)').run(userId, 'generate', amount, toolId);
}

// ════════════════════════════════════════════════════
//  EMAIL / PASSWORD AUTH
// ════════════════════════════════════════════════════

// REGISTER
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { name, email, password, plan = 'free' } = req.body;
  if (!name?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase())) return res.status(409).json({ error: 'An account with this email already exists' });

  const planCredits = { free: 2500, pro: 10000, agency: 999999 };
  const credits = planCredits[plan] || 2500;
  const hash = await bcrypt.hash(password, 12);

  try {
    const result = db.prepare('INSERT INTO users (name, email, password, plan, credits, credits_max) VALUES (?, ?, ?, ?, ?, ?)').run(name.trim(), email.toLowerCase().trim(), hash, plan, credits, credits);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ token: makeToken(user.id), user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// LOGIN
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND is_active = 1').get(email.toLowerCase().trim());
  if (!user || !user.password || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid email or password' });
  db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
  res.json({ token: makeToken(user.id), user: safeUser(user) });
});

// ════════════════════════════════════════════════════
//  GOOGLE OAUTH 2.0
// ════════════════════════════════════════════════════

// Step 1 — Redirect user to Google login
app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_ID) return res.status(500).send('Google OAuth not configured. Add GOOGLE_CLIENT_ID to .env');

  const params = new URLSearchParams({
    client_id: GOOGLE_ID,
    redirect_uri: `${APP_URL}/api/auth/google/callback`,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account'
  });

  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

// Step 2 — Google redirects back here with a code
app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error || !code) return res.redirect('/login.html?error=google_cancelled');

  try {
    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_ID,
        client_secret: GOOGLE_SECRET,
        redirect_uri: `${APP_URL}/api/auth/google/callback`,
        grant_type: 'authorization_code'
      })
    });

    const tokens = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokens.error_description || 'Token exchange failed');

    // Get user info from Google
    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });

    const googleUser = await userRes.json();
    if (!googleUser.email) throw new Error('Could not get email from Google');

    // Find or create user in database
    let user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(googleUser.id);

    if (!user) {
      // Check if email already exists (link accounts)
      user = db.prepare('SELECT * FROM users WHERE email = ?').get(googleUser.email.toLowerCase());

      if (user) {
        // Link Google to existing account
        db.prepare('UPDATE users SET google_id = ?, avatar = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?')
          .run(googleUser.id, googleUser.picture, user.id);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
      } else {
        // Create brand new account
        const result = db.prepare(
          'INSERT INTO users (name, email, google_id, avatar, plan, credits, credits_max) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(googleUser.name, googleUser.email.toLowerCase(), googleUser.id, googleUser.picture, 'free', 2500, 2500);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      }
    } else {
      // Update last login and avatar
      db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP, avatar = ? WHERE id = ?').run(googleUser.picture, user.id);
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    }

    if (!user.is_active) return res.redirect('/login.html?error=account_disabled');

    // Generate JWT and redirect to app
    const token = makeToken(user.id);
    res.redirect(`/app.html?token=${token}&name=${encodeURIComponent(user.name)}`);

  } catch (err) {
    console.error('Google OAuth error:', err.message);
    res.redirect(`/login.html?error=${encodeURIComponent(err.message)}`);
  }
});

// ════════════════════════════════════════════════════
//  USER PROFILE
// ════════════════════════════════════════════════════
app.get('/api/auth/me', requireAuth, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, name: u.name, email: u.email, plan: u.plan, credits: u.credits, credits_max: u.credits_max, avatar: u.avatar, brand_name: u.brand_name, brand_desc: u.brand_desc, brand_tone: u.brand_tone });
});

app.put('/api/auth/me', requireAuth, (req, res) => {
  const { name, brand_name, brand_desc, brand_tone, groq_key } = req.body;
  db.prepare('UPDATE users SET name=COALESCE(?,name), brand_name=COALESCE(?,brand_name), brand_desc=COALESCE(?,brand_desc), brand_tone=COALESCE(?,brand_tone), groq_key=COALESCE(?,groq_key) WHERE id=?')
    .run(name, brand_name, brand_desc, brand_tone, groq_key, req.user.id);
  res.json({ success: true });
});

app.put('/api/auth/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!req.user.password) return res.status(400).json({ error: 'This account uses Google login. Password change not available.' });
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'Minimum 8 characters' });
  if (!(await bcrypt.compare(currentPassword, req.user.password))) return res.status(401).json({ error: 'Current password is incorrect' });
  db.prepare('UPDATE users SET password=? WHERE id=?').run(await bcrypt.hash(newPassword, 12), req.user.id);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  AI CHAT — Groq (FREE)
// ════════════════════════════════════════════════════
app.post('/api/chat', requireAuth, apiLimiter, async (req, res) => {
  const { messages, model = 'llama-3.3-70b-versatile' } = req.body;
  if (!Array.isArray(messages)) return res.status(400).json({ error: 'Messages array required' });

  const groqKey = req.user.groq_key || GROQ_KEY;
  if (!groqKey) return res.status(400).json({ error: 'Groq API key not set. Add GROQ_API_KEY to your .env file.' });
  if (req.user.credits < 1) return res.status(402).json({ error: 'No credits remaining. Please upgrade your plan.' });

  const systemPrompt = `You are M-SM AI, an expert AI marketing strategist and copywriter. You specialise in content creation, SEO, email marketing, social media strategy, ad campaigns, brand positioning, and all aspects of digital marketing. Be specific, practical, and results-focused. When giving copy examples format them clearly with labels. User brand: ${req.user.brand_name || 'Not set'}. Preferred tone: ${req.user.brand_tone || 'Professional'}.`;

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        max_tokens: 1024,
        temperature: 0.7,
        messages: [{ role: 'system', content: systemPrompt }, ...messages.slice(-20)]
      })
    });

    if (!response.ok) {
      const e = await response.json();
      throw new Error(e.error?.message || 'Groq API error');
    }

    const data = await response.json();
    spendCredits(req.user.id, 5, 'chat');
    res.json({ success: true, message: data.choices[0].message.content, model: data.model });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════
//  CONTENT GENERATION — Groq (FREE)
// ════════════════════════════════════════════════════
app.post('/api/generate', requireAuth, apiLimiter, async (req, res) => {
  const { prompt, toolId, toolName, tone = 'Professional', variants = 1 } = req.body;
  if (!prompt?.trim()) return res.status(400).json({ error: 'Prompt is required' });

  const groqKey = req.user.groq_key || GROQ_KEY;
  if (!groqKey) return res.status(400).json({ error: 'Groq API key not set. Add GROQ_API_KEY to your .env file.' });
  if (req.user.credits < 10) return res.status(402).json({ error: 'Insufficient credits. Please upgrade.' });

  const fullPrompt = variants > 1
    ? prompt + `\n\nGenerate ${variants} clearly distinct variants. Label each one exactly as: ═══ VARIANT 1 ═══, ═══ VARIANT 2 ═══, etc.`
    : prompt;

  const systemPrompt = `You are M-SM AI, an elite marketing copywriter and strategist with 15+ years of experience. You write compelling, high-converting content that gets real results. Tone: ${tone}. Brand context: ${req.user.brand_desc || 'General marketing'}. Be direct, specific, and persuasive. Format output clearly and professionally.`;

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        max_tokens: 2500,
        temperature: 0.75,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: fullPrompt }
        ]
      })
    });

    if (!response.ok) {
      const e = await response.json();
      throw new Error(e.error?.message || 'Groq error');
    }

    const data = await response.json();
    const text = data.choices[0].message.content;
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    const creditsUsed = Math.max(10, Math.ceil(wordCount / 10));

    spendCredits(req.user.id, creditsUsed, toolId);

    // Auto-save document
    const r = db.prepare('INSERT INTO documents (user_id, title, content, tool_id, tool_name, word_count) VALUES (?, ?, ?, ?, ?, ?)')
      .run(req.user.id, `${toolName || 'Content'} — ${new Date().toLocaleDateString()}`, text, toolId, toolName, wordCount);

    res.json({ success: true, text, wordCount, creditsUsed, docId: r.lastInsertRowid, model: data.model });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════
//  DOCUMENTS CRUD
// ════════════════════════════════════════════════════
app.get('/api/documents', requireAuth, (req, res) => {
  const { page = 1, limit = 30 } = req.query;
  const offset = (page - 1) * limit;
  const docs  = db.prepare('SELECT * FROM documents WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.user.id, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM documents WHERE user_id = ?').get(req.user.id);
  res.json({ documents: docs, total: total.c });
});

app.get('/api/documents/:id', requireAuth, (req, res) => {
  const doc = db.prepare('SELECT * FROM documents WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  res.json(doc);
});

app.post('/api/documents', requireAuth, (req, res) => {
  const { title, content, tool_id, tool_name } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const wc = (content || '').split(/\s+/).filter(Boolean).length;
  const r  = db.prepare('INSERT INTO documents (user_id, title, content, tool_id, tool_name, word_count) VALUES (?, ?, ?, ?, ?, ?)').run(req.user.id, title, content || '', tool_id, tool_name, wc);
  res.status(201).json({ id: r.lastInsertRowid, success: true });
});

app.put('/api/documents/:id', requireAuth, (req, res) => {
  const { title, content } = req.body;
  const wc = (content || '').split(/\s+/).filter(Boolean).length;
  const r  = db.prepare('UPDATE documents SET title=COALESCE(?,title), content=COALESCE(?,content), word_count=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?').run(title, content, wc, req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

app.delete('/api/documents/:id', requireAuth, (req, res) => {
  const r = db.prepare('DELETE FROM documents WHERE id=? AND user_id=?').run(req.params.id, req.user.id);
  if (!r.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  DASHBOARD STATS
// ════════════════════════════════════════════════════
app.get('/api/stats', requireAuth, (req, res) => {
  const uid = req.user.id;
  const totalDocs  = db.prepare('SELECT COUNT(*) as c FROM documents WHERE user_id=?').get(uid);
  const totalWords = db.prepare('SELECT COALESCE(SUM(word_count),0) as w FROM documents WHERE user_id=?').get(uid);
  const weekDocs   = db.prepare("SELECT COUNT(*) as c FROM documents WHERE user_id=? AND created_at>=date('now','-7 days')").get(uid);
  const topTool    = db.prepare('SELECT tool_name, COUNT(*) as uses FROM documents WHERE user_id=? AND tool_name IS NOT NULL GROUP BY tool_name ORDER BY uses DESC LIMIT 1').get(uid);
  const recentDocs = db.prepare('SELECT * FROM documents WHERE user_id=? ORDER BY created_at DESC LIMIT 5').all(uid);
  res.json({
    totalDocuments: totalDocs.c, totalWords: totalWords.w,
    creditsUsed: req.user.credits_max - req.user.credits,
    creditsRemaining: req.user.credits, creditsMax: req.user.credits_max,
    docsThisWeek: weekDocs.c, topTool: topTool?.tool_name || 'Blog Writer',
    recentDocuments: recentDocs
  });
});

// ════════════════════════════════════════════════════
//  API KEYS
// ════════════════════════════════════════════════════
app.put('/api/keys', requireAuth, (req, res) => {
  const { groq_key } = req.body;
  db.prepare('UPDATE users SET groq_key=COALESCE(?,groq_key) WHERE id=?').run(groq_key || null, req.user.id);
  res.json({ success: true });
});

app.get('/api/keys', requireAuth, (req, res) => {
  res.json({
    has_groq: !!(req.user.groq_key || GROQ_KEY),
    groq_preview: req.user.groq_key ? req.user.groq_key.slice(0,12)+'…' : (GROQ_KEY ? '✓ Server key active' : null)
  });
});

// ════════════════════════════════════════════════════
//  HEALTH CHECK
// ════════════════════════════════════════════════════
app.get('/api/health', (req, res) => {
  const users = db.prepare('SELECT COUNT(*) as c FROM users').get();
  res.json({ status: 'ok', app: 'M-SM AI', version: '2.1.0', users: users.c, groq: !!GROQ_KEY, google: !!GOOGLE_ID, timestamp: new Date().toISOString() });
});

// Page routes
app.get('/app',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/login',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));

// ════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║      M-SM AI — Production Server        ║
╠══════════════════════════════════════════╣
║  URL:  http://localhost:${PORT}              ║
║  DB:   SQLite ✓                         ║
╠══════════════════════════════════════════╣
║  Groq AI:     ${GROQ_KEY   ? '✓ Ready (FREE)      ' : '✗ Add GROQ_API_KEY   '}  ║
║  Google Auth: ${GOOGLE_ID  ? '✓ Configured        ' : '✗ Add GOOGLE_CLIENT_ID'} ║
╚══════════════════════════════════════════╝

  http://localhost:${PORT}             ← Landing page
  http://localhost:${PORT}/login.html  ← Login
  http://localhost:${PORT}/signup.html ← Sign up
  http://localhost:${PORT}/app.html    ← Dashboard
`);
});
