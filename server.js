/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║     M-SM AI — Production Server with PostgreSQL         ║
 * ║     Enterprise-grade database for scaling businesses    ║
 * ║     Groq AI (FREE) + Google OAuth + JWT Auth            ║
 * ╚══════════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
const { Pool }  = require('pg');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET    = process.env.JWT_SECRET || 'msm-ai-dev-secret';
const GROQ_KEY      = process.env.GROQ_API_KEY;
const GOOGLE_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const APP_URL       = process.env.APP_URL || `http://localhost:${PORT}`;

// ════════════════════════════════════════════════════
//  POSTGRESQL CONNECTION
// ════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test connection and create tables
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        name          VARCHAR(255) NOT NULL,
        email         VARCHAR(255) UNIQUE NOT NULL,
        password      VARCHAR(255),
        google_id     VARCHAR(255) UNIQUE,
        avatar        TEXT,
        plan          VARCHAR(50) DEFAULT 'free',
        credits       INTEGER DEFAULT 2500,
        credits_max   INTEGER DEFAULT 2500,
        groq_key      TEXT,
        brand_name    VARCHAR(255),
        brand_desc    TEXT,
        brand_tone    VARCHAR(100) DEFAULT 'Professional',
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login    TIMESTAMP,
        is_active     BOOLEAN DEFAULT TRUE
      );

      CREATE TABLE IF NOT EXISTS documents (
        id          SERIAL PRIMARY KEY,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title       VARCHAR(500) NOT NULL,
        content     TEXT,
        tool_id     VARCHAR(100),
        tool_name   VARCHAR(255),
        word_count  INTEGER DEFAULT 0,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS usage_log (
        id           SERIAL PRIMARY KEY,
        user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        action       VARCHAR(100) NOT NULL,
        credits_used INTEGER DEFAULT 0,
        tool_id      VARCHAR(100),
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
      CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_usage_log_user_id ON usage_log(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);
    console.log('✓ PostgreSQL database ready');
  } finally {
    client.release();
  }
}

initDB().catch(err => {
  console.error('✗ Database connection failed:', err.message);
  console.error('Make sure DATABASE_URL is set in your environment variables');
});

// DB helper
const db = {
  query: (text, params) => pool.query(text, params),
  getOne: async (text, params) => { const r = await pool.query(text, params); return r.rows[0] || null; },
  getAll: async (text, params) => { const r = await pool.query(text, params); return r.rows; },
  run: async (text, params) => { const r = await pool.query(text, params); return r; }
};

// ════════════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many attempts. Try again in 15 minutes.' } });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests. Please slow down.' } });

// ════════════════════════════════════════════════════
//  AUTH HELPERS
// ════════════════════════════════════════════════════
function makeToken(userId) { return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' }); }

function safeUser(u) {
  return {
    id: u.id, name: u.name, email: u.email,
    plan: u.plan, credits: u.credits, credits_max: u.credits_max,
    avatar: u.avatar, brand_name: u.brand_name,
    brand_desc: u.brand_desc, brand_tone: u.brand_tone
  };
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Please log in to continue' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    const user = await db.getOne('SELECT * FROM users WHERE id = $1 AND is_active = TRUE', [decoded.userId]);
    if (!user) return res.status(401).json({ error: 'Account not found' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

async function spendCredits(userId, amount, toolId = null) {
  await db.run('UPDATE users SET credits = GREATEST(0, credits - $1) WHERE id = $2', [amount, userId]);
  await db.run('INSERT INTO usage_log (user_id, action, credits_used, tool_id) VALUES ($1, $2, $3, $4)', [userId, 'generate', amount, toolId]);
}

// ════════════════════════════════════════════════════
//  AUTH — REGISTER
// ════════════════════════════════════════════════════
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, plan = 'free' } = req.body;
    if (!name?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });

    const existing = await db.getOne('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

    const planCredits = { free: 2500, pro: 10000, agency: 999999 };
    const credits = planCredits[plan] || 2500;
    const hash = await bcrypt.hash(password, 12);

    const result = await db.getOne(
      'INSERT INTO users (name, email, password, plan, credits, credits_max) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [name.trim(), email.toLowerCase(), hash, plan, credits, credits]
    );
    res.status(201).json({ token: makeToken(result.id), user: safeUser(result) });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// ════════════════════════════════════════════════════
//  AUTH — LOGIN
// ════════════════════════════════════════════════════
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await db.getOne('SELECT * FROM users WHERE email = $1 AND is_active = TRUE', [email.toLowerCase()]);
    if (!user || !user.password || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    res.json({ token: makeToken(user.id), user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════
//  GOOGLE OAUTH
// ════════════════════════════════════════════════════
app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_ID) return res.status(500).send('Google OAuth not configured. Add GOOGLE_CLIENT_ID to environment variables.');
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

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/login.html?error=google_cancelled');

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: GOOGLE_ID, client_secret: GOOGLE_SECRET, redirect_uri: `${APP_URL}/api/auth/google/callback`, grant_type: 'authorization_code' })
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(tokens.error_description || 'Token exchange failed');

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    const gUser = await userRes.json();
    if (!gUser.email) throw new Error('Could not get email from Google');

    let user = await db.getOne('SELECT * FROM users WHERE google_id = $1', [gUser.id]);
    if (!user) {
      user = await db.getOne('SELECT * FROM users WHERE email = $1', [gUser.email.toLowerCase()]);
      if (user) {
        user = await db.getOne('UPDATE users SET google_id=$1, avatar=$2, last_login=CURRENT_TIMESTAMP WHERE id=$3 RETURNING *', [gUser.id, gUser.picture, user.id]);
      } else {
        user = await db.getOne(
          'INSERT INTO users (name, email, google_id, avatar, plan, credits, credits_max) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
          [gUser.name, gUser.email.toLowerCase(), gUser.id, gUser.picture, 'free', 2500, 2500]
        );
      }
    } else {
      user = await db.getOne('UPDATE users SET last_login=CURRENT_TIMESTAMP, avatar=$1 WHERE id=$2 RETURNING *', [gUser.picture, user.id]);
    }

    if (!user.is_active) return res.redirect('/login.html?error=account_disabled');
    res.redirect(`/app.html?token=${makeToken(user.id)}&name=${encodeURIComponent(user.name)}`);
  } catch (err) {
    console.error('Google OAuth error:', err.message);
    res.redirect(`/login.html?error=${encodeURIComponent(err.message)}`);
  }
});

// ════════════════════════════════════════════════════
//  PROFILE
// ════════════════════════════════════════════════════
app.get('/api/auth/me', requireAuth, (req, res) => res.json(safeUser(req.user)));

app.put('/api/auth/me', requireAuth, async (req, res) => {
  const { name, brand_name, brand_desc, brand_tone, groq_key } = req.body;
  const user = await db.getOne(
    'UPDATE users SET name=COALESCE($1,name), brand_name=COALESCE($2,brand_name), brand_desc=COALESCE($3,brand_desc), brand_tone=COALESCE($4,brand_tone), groq_key=COALESCE($5,groq_key) WHERE id=$6 RETURNING *',
    [name, brand_name, brand_desc, brand_tone, groq_key, req.user.id]
  );
  res.json({ success: true, user: safeUser(user) });
});

app.put('/api/auth/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!req.user.password) return res.status(400).json({ error: 'This account uses Google login.' });
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'Minimum 8 characters' });
  if (!(await bcrypt.compare(currentPassword, req.user.password))) return res.status(401).json({ error: 'Current password incorrect' });
  await db.run('UPDATE users SET password=$1 WHERE id=$2', [await bcrypt.hash(newPassword, 12), req.user.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  AI CHAT — Groq FREE
// ════════════════════════════════════════════════════
app.post('/api/chat', requireAuth, apiLimiter, async (req, res) => {
  try {
    const { messages, model = 'llama-3.3-70b-versatile' } = req.body;
    if (!Array.isArray(messages)) return res.status(400).json({ error: 'Messages array required' });

    const groqKey = req.user.groq_key || GROQ_KEY;
    if (!groqKey) return res.status(400).json({ error: 'Groq API key not configured.' });
    if (req.user.credits < 1) return res.status(402).json({ error: 'No credits remaining. Please upgrade.' });

    const systemPrompt = `You are M-SM AI, an expert AI marketing strategist and copywriter. Specialise in content creation, SEO, email marketing, social media, ad campaigns, and brand strategy. Be specific, practical, and results-focused. User brand: ${req.user.brand_name || 'Not set'}. Tone: ${req.user.brand_tone || 'Professional'}.`;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, max_tokens: 1024, temperature: 0.7, messages: [{ role: 'system', content: systemPrompt }, ...messages.slice(-20)] })
    });

    if (!response.ok) { const e = await response.json(); throw new Error(e.error?.message || 'Groq API error'); }
    const data = await response.json();
    await spendCredits(req.user.id, 5, 'chat');
    res.json({ success: true, message: data.choices[0].message.content, model: data.model });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════
//  CONTENT GENERATION — Groq FREE
// ════════════════════════════════════════════════════
app.post('/api/generate', requireAuth, apiLimiter, async (req, res) => {
  try {
    const { prompt, toolId, toolName, tone = 'Professional', variants = 1 } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: 'Prompt required' });

    const groqKey = req.user.groq_key || GROQ_KEY;
    if (!groqKey) return res.status(400).json({ error: 'Groq API key not configured.' });
    if (req.user.credits < 10) return res.status(402).json({ error: 'Insufficient credits. Please upgrade.' });

    const fullPrompt = variants > 1
      ? prompt + `\n\nGenerate ${variants} distinct variants labeled: ═══ VARIANT 1 ═══, ═══ VARIANT 2 ═══, etc.`
      : prompt;

    const systemPrompt = `You are M-SM AI, an elite marketing copywriter with 15+ years experience. Tone: ${tone}. Brand: ${req.user.brand_desc || 'General marketing'}. Be direct, persuasive, and conversion-focused. Format output clearly.`;

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'llama-3.3-70b-versatile', max_tokens: 2500, temperature: 0.75, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: fullPrompt }] })
    });

    if (!response.ok) { const e = await response.json(); throw new Error(e.error?.message || 'Groq error'); }
    const data = await response.json();
    const text = data.choices[0].message.content;
    const wordCount = text.split(/\s+/).filter(Boolean).length;
    const creditsUsed = Math.max(10, Math.ceil(wordCount / 10));

    await spendCredits(req.user.id, creditsUsed, toolId);

    const doc = await db.getOne(
      'INSERT INTO documents (user_id, title, content, tool_id, tool_name, word_count) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [req.user.id, `${toolName || 'Content'} — ${new Date().toLocaleDateString()}`, text, toolId, toolName, wordCount]
    );

    res.json({ success: true, text, wordCount, creditsUsed, docId: doc.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════
//  DOCUMENTS CRUD
// ════════════════════════════════════════════════════
app.get('/api/documents', requireAuth, async (req, res) => {
  const { page = 1, limit = 30 } = req.query;
  const offset = (page - 1) * limit;
  const docs  = await db.getAll('SELECT * FROM documents WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [req.user.id, limit, offset]);
  const total = await db.getOne('SELECT COUNT(*) as c FROM documents WHERE user_id=$1', [req.user.id]);
  res.json({ documents: docs, total: parseInt(total.c) });
});

app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await db.getOne('SELECT * FROM documents WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  res.json(doc);
});

app.post('/api/documents', requireAuth, async (req, res) => {
  const { title, content, tool_id, tool_name } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const wc  = (content || '').split(/\s+/).filter(Boolean).length;
  const doc = await db.getOne('INSERT INTO documents (user_id,title,content,tool_id,tool_name,word_count) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [req.user.id, title, content || '', tool_id, tool_name, wc]);
  res.status(201).json({ id: doc.id, success: true });
});

app.put('/api/documents/:id', requireAuth, async (req, res) => {
  const { title, content } = req.body;
  const wc = (content || '').split(/\s+/).filter(Boolean).length;
  await db.run('UPDATE documents SET title=COALESCE($1,title), content=COALESCE($2,content), word_count=$3, updated_at=CURRENT_TIMESTAMP WHERE id=$4 AND user_id=$5', [title, content, wc, req.params.id, req.user.id]);
  res.json({ success: true });
});

app.delete('/api/documents/:id', requireAuth, async (req, res) => {
  await db.run('DELETE FROM documents WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  DASHBOARD STATS
// ════════════════════════════════════════════════════
app.get('/api/stats', requireAuth, async (req, res) => {
  const uid = req.user.id;
  const [totalDocs, totalWords, weekDocs, topTool, recentDocs] = await Promise.all([
    db.getOne('SELECT COUNT(*) as c FROM documents WHERE user_id=$1', [uid]),
    db.getOne('SELECT COALESCE(SUM(word_count),0) as w FROM documents WHERE user_id=$1', [uid]),
    db.getOne("SELECT COUNT(*) as c FROM documents WHERE user_id=$1 AND created_at>=NOW()-INTERVAL '7 days'", [uid]),
    db.getOne('SELECT tool_name, COUNT(*) as uses FROM documents WHERE user_id=$1 AND tool_name IS NOT NULL GROUP BY tool_name ORDER BY uses DESC LIMIT 1', [uid]),
    db.getAll('SELECT * FROM documents WHERE user_id=$1 ORDER BY created_at DESC LIMIT 5', [uid])
  ]);
  res.json({
    totalDocuments: parseInt(totalDocs.c),
    totalWords: parseInt(totalWords.w),
    creditsUsed: req.user.credits_max - req.user.credits,
    creditsRemaining: req.user.credits,
    creditsMax: req.user.credits_max,
    docsThisWeek: parseInt(weekDocs.c),
    topTool: topTool?.tool_name || 'Blog Writer',
    recentDocuments: recentDocs
  });
});

// ════════════════════════════════════════════════════
//  API KEYS
// ════════════════════════════════════════════════════
app.put('/api/keys', requireAuth, async (req, res) => {
  const { groq_key } = req.body;
  await db.run('UPDATE users SET groq_key=COALESCE($1,groq_key) WHERE id=$2', [groq_key || null, req.user.id]);
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
app.get('/api/health', async (req, res) => {
  try {
    const users = await db.getOne('SELECT COUNT(*) as c FROM users');
    const docs  = await db.getOne('SELECT COUNT(*) as c FROM documents');
    res.json({
      status: 'ok', app: 'M-SM AI', version: '3.0.0',
      database: 'PostgreSQL',
      users: parseInt(users.c),
      documents: parseInt(docs.c),
      groq: !!GROQ_KEY,
      google: !!GOOGLE_ID,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
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
╔══════════════════════════════════════════════╗
║       M-SM AI — Enterprise Server v3.0      ║
╠══════════════════════════════════════════════╣
║  URL:      http://localhost:${PORT}              ║
║  Database: PostgreSQL ✓                     ║
╠══════════════════════════════════════════════╣
║  Groq AI:     ${GROQ_KEY      ? '✓ Ready (FREE)        ' : '✗ Add GROQ_API_KEY     '}  ║
║  Google Auth: ${GOOGLE_ID     ? '✓ Configured          ' : '✗ Add GOOGLE_CLIENT_ID '}  ║
║  Database:    ${process.env.DATABASE_URL ? '✓ PostgreSQL connected' : '✗ Add DATABASE_URL    '}  ║
╚══════════════════════════════════════════════╝
`);
});
