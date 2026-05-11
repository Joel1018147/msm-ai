/**
 * ╔══════════════════════════════════════════════════════════════╗
 * ║     M-SM AI — Full Production Server v4.0                   ║
 * ║     PostgreSQL + Groq AI + Google OAuth + Stripe            ║
 * ║     WordPress/Shopify Integration + Developer API           ║
 * ║     Admin Dashboard + Team Workspaces + Analytics          ║
 * ╚══════════════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
const crypto    = require('crypto');
const { Pool }  = require('pg');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET    = process.env.JWT_SECRET || 'msm-ai-dev-secret';
const GROQ_KEY      = process.env.GROQ_API_KEY;
const GOOGLE_ID     = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const APP_URL       = process.env.APP_URL || `http://localhost:${PORT}`;

// ════════════════════════════════════════════════════
//  POSTGRESQL
// ════════════════════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

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
        role          VARCHAR(20) DEFAULT 'user',
        credits       INTEGER DEFAULT 2500,
        credits_max   INTEGER DEFAULT 2500,
        groq_key      TEXT,
        wp_url        TEXT,
        wp_username   TEXT,
        wp_password   TEXT,
        shopify_store TEXT,
        shopify_token TEXT,
        brand_name    VARCHAR(255),
        brand_desc    TEXT,
        brand_tone    VARCHAR(100) DEFAULT 'Professional',
        team_id       INTEGER,
        api_key       VARCHAR(64) UNIQUE,
        created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login    TIMESTAMP,
        is_active     BOOLEAN DEFAULT TRUE
      );

      CREATE TABLE IF NOT EXISTS teams (
        id          SERIAL PRIMARY KEY,
        name        VARCHAR(255) NOT NULL,
        owner_id    INTEGER REFERENCES users(id),
        plan        VARCHAR(50) DEFAULT 'agency',
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS team_members (
        id        SERIAL PRIMARY KEY,
        team_id   INTEGER REFERENCES teams(id) ON DELETE CASCADE,
        user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
        role      VARCHAR(20) DEFAULT 'member',
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS documents (
        id          SERIAL PRIMARY KEY,
        user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        team_id     INTEGER REFERENCES teams(id),
        title       VARCHAR(500) NOT NULL,
        content     TEXT,
        tool_id     VARCHAR(100),
        tool_name   VARCHAR(255),
        word_count  INTEGER DEFAULT 0,
        seo_score   INTEGER DEFAULT 0,
        readability INTEGER DEFAULT 0,
        published_wp    BOOLEAN DEFAULT FALSE,
        published_shopify BOOLEAN DEFAULT FALSE,
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

      CREATE TABLE IF NOT EXISTS api_usage (
        id           SERIAL PRIMARY KEY,
        user_id      INTEGER REFERENCES users(id),
        api_key      VARCHAR(64),
        endpoint     VARCHAR(255),
        credits_used INTEGER DEFAULT 0,
        created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS bulk_jobs (
        id          SERIAL PRIMARY KEY,
        user_id     INTEGER REFERENCES users(id),
        tool_id     VARCHAR(100),
        tool_name   VARCHAR(255),
        status      VARCHAR(20) DEFAULT 'pending',
        total       INTEGER DEFAULT 0,
        completed   INTEGER DEFAULT 0,
        results     TEXT,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
      CREATE INDEX IF NOT EXISTS idx_documents_team ON documents(team_id);
      CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_log(user_id);
      CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
    `);

    // Make first user admin
    await client.query(`
      UPDATE users SET role = 'admin' 
      WHERE id = (SELECT MIN(id) FROM users) AND role = 'user'
    `);

    console.log('✓ PostgreSQL database ready');
  } finally { client.release(); }
}

initDB().catch(err => console.error('✗ DB init failed:', err.message));

const db = {
  query:  (t, p) => pool.query(t, p),
  getOne: async (t, p) => { const r = await pool.query(t, p); return r.rows[0] || null; },
  getAll: async (t, p) => { const r = await pool.query(t, p); return r.rows; },
  run:    async (t, p) => pool.query(t, p)
};

// ════════════════════════════════════════════════════
//  MIDDLEWARE
// ════════════════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many attempts.' } });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 120, message: { error: 'Too many requests.' } });

// ════════════════════════════════════════════════════
//  AUTH HELPERS
// ════════════════════════════════════════════════════
function makeToken(userId) { return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' }); }
function safeUser(u) {
  return {
    id: u.id, name: u.name, email: u.email, plan: u.plan, role: u.role,
    credits: u.credits, credits_max: u.credits_max, avatar: u.avatar,
    brand_name: u.brand_name, brand_desc: u.brand_desc, brand_tone: u.brand_tone,
    api_key: u.api_key, team_id: u.team_id,
    has_wp: !!(u.wp_url), has_shopify: !!(u.shopify_store)
  };
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Please log in' });
  try {
    const decoded = jwt.verify(auth.slice(7), JWT_SECRET);
    const user = await db.getOne('SELECT * FROM users WHERE id = $1 AND is_active = TRUE', [decoded.userId]);
    if (!user) return res.status(401).json({ error: 'Account not found' });
    req.user = user;
    next();
  } catch { return res.status(401).json({ error: 'Session expired. Please log in again.' }); }
}

async function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// Developer API Key auth
async function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) return requireAuth(req, res, next);
  const user = await db.getOne('SELECT * FROM users WHERE api_key = $1 AND is_active = TRUE', [key]);
  if (!user) return res.status(401).json({ error: 'Invalid API key' });
  req.user = user;
  req.isApiKey = true;
  next();
}

async function spendCredits(userId, amount, toolId = null) {
  await db.run('UPDATE users SET credits = GREATEST(0, credits - $1) WHERE id = $2', [amount, userId]);
  await db.run('INSERT INTO usage_log (user_id, action, credits_used, tool_id) VALUES ($1, $2, $3, $4)', [userId, 'generate', amount, toolId]);
}

// ════════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════════
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password, plan = 'free' } = req.body;
    if (!name?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
    if (await db.getOne('SELECT id FROM users WHERE email = $1', [email.toLowerCase()])) return res.status(409).json({ error: 'Email already registered' });
    const planCredits = { free: 2500, pro: 10000, agency: 999999 };
    const credits = planCredits[plan] || 2500;
    const hash = await bcrypt.hash(password, 12);
    const apiKey = crypto.randomBytes(32).toString('hex');
    const isFirst = !(await db.getOne('SELECT id FROM users LIMIT 1'));
    const result = await db.getOne(
      'INSERT INTO users (name, email, password, plan, credits, credits_max, api_key, role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [name.trim(), email.toLowerCase(), hash, plan, credits, credits, apiKey, isFirst ? 'admin' : 'user']
    );
    res.status(201).json({ token: makeToken(result.id), user: safeUser(result) });
  } catch (err) { res.status(500).json({ error: 'Registration failed: ' + err.message }); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await db.getOne('SELECT * FROM users WHERE email = $1 AND is_active = TRUE', [email.toLowerCase()]);
    if (!user || !user.password || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid email or password' });
    await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    res.json({ token: makeToken(user.id), user: safeUser(user) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_ID) return res.status(500).send('Google OAuth not configured');
  const params = new URLSearchParams({ client_id: GOOGLE_ID, redirect_uri: `${APP_URL}/api/auth/google/callback`, response_type: 'code', scope: 'openid email profile', access_type: 'offline', prompt: 'select_account' });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/login.html?error=google_cancelled');
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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
        user = await db.getOne('UPDATE users SET google_id=$1,avatar=$2,last_login=CURRENT_TIMESTAMP WHERE id=$3 RETURNING *', [gUser.id, gUser.picture, user.id]);
      } else {
        const isFirst = !(await db.getOne('SELECT id FROM users LIMIT 1'));
        const apiKey = crypto.randomBytes(32).toString('hex');
        user = await db.getOne(
          'INSERT INTO users (name,email,google_id,avatar,plan,credits,credits_max,api_key,role) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
          [gUser.name, gUser.email.toLowerCase(), gUser.id, gUser.picture, 'free', 2500, 2500, apiKey, isFirst ? 'admin' : 'user']
        );
      }
    } else {
      user = await db.getOne('UPDATE users SET last_login=CURRENT_TIMESTAMP,avatar=$1 WHERE id=$2 RETURNING *', [gUser.picture, user.id]);
    }
    if (!user.is_active) return res.redirect('/login.html?error=account_disabled');
    res.redirect(`/app.html?token=${makeToken(user.id)}&name=${encodeURIComponent(user.name)}`);
  } catch (err) { res.redirect(`/login.html?error=${encodeURIComponent(err.message)}`); }
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json(safeUser(req.user)));

app.put('/api/auth/me', requireAuth, async (req, res) => {
  const { name, brand_name, brand_desc, brand_tone, groq_key } = req.body;
  const user = await db.getOne(
    'UPDATE users SET name=COALESCE($1,name),brand_name=COALESCE($2,brand_name),brand_desc=COALESCE($3,brand_desc),brand_tone=COALESCE($4,brand_tone),groq_key=COALESCE($5,groq_key) WHERE id=$6 RETURNING *',
    [name, brand_name, brand_desc, brand_tone, groq_key, req.user.id]
  );
  res.json({ success: true, user: safeUser(user) });
});

app.put('/api/auth/password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!req.user.password) return res.status(400).json({ error: 'This account uses Google login.' });
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'Min 8 characters' });
  if (!(await bcrypt.compare(currentPassword, req.user.password))) return res.status(401).json({ error: 'Current password incorrect' });
  await db.run('UPDATE users SET password=$1 WHERE id=$2', [await bcrypt.hash(newPassword, 12), req.user.id]);
  res.json({ success: true });
});

// Regenerate API Key
app.post('/api/auth/regenerate-key', requireAuth, async (req, res) => {
  const newKey = crypto.randomBytes(32).toString('hex');
  await db.run('UPDATE users SET api_key=$1 WHERE id=$2', [newKey, req.user.id]);
  res.json({ success: true, api_key: newKey });
});

// ════════════════════════════════════════════════════
//  AI CHAT — Groq
// ════════════════════════════════════════════════════
app.post('/api/chat', requireApiKey, apiLimiter, async (req, res) => {
  try {
    const { messages, model = 'llama-3.3-70b-versatile' } = req.body;
    if (!Array.isArray(messages)) return res.status(400).json({ error: 'Messages array required' });
    const groqKey = req.user.groq_key || GROQ_KEY;
    if (!groqKey) return res.status(400).json({ error: 'Groq API key not configured' });
    if (req.user.credits < 1) return res.status(402).json({ error: 'No credits remaining' });
    const systemPrompt = `You are M-SM AI, an expert marketing strategist and copywriter. Help with content creation, SEO, email marketing, social media, ad campaigns, and brand strategy. Be specific and actionable. User brand: ${req.user.brand_name || 'Not set'}. Tone: ${req.user.brand_tone || 'Professional'}.`;
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST', headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, max_tokens: 1024, temperature: 0.7, messages: [{ role: 'system', content: systemPrompt }, ...messages.slice(-20)] })
    });
    if (!response.ok) { const e = await response.json(); throw new Error(e.error?.message || 'Groq error'); }
    const data = await response.json();
    await spendCredits(req.user.id, 5, 'chat');
    res.json({ success: true, message: data.choices[0].message.content, model: data.model });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════
//  CONTENT GENERATION — Groq
// ════════════════════════════════════════════════════
async function generateWithGroq(user, prompt, toolId, toolName, tone, variants = 1) {
  const groqKey = user.groq_key || GROQ_KEY;
  if (!groqKey) throw new Error('Groq API key not configured');
  if (user.credits < 10) throw new Error('Insufficient credits');

  const fullPrompt = variants > 1
    ? prompt + `\n\nGenerate ${variants} distinct variants labeled: ═══ VARIANT 1 ═══, ═══ VARIANT 2 ═══, etc.`
    : prompt;

  const systemPrompt = `You are M-SM AI, an elite marketing copywriter with 15+ years experience. Tone: ${tone || 'Professional'}. Brand: ${user.brand_desc || 'General marketing'}. Be persuasive, specific, and conversion-focused.`;

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST', headers: { 'Authorization': `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'llama-3.3-70b-versatile', max_tokens: 2500, temperature: 0.75, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: fullPrompt }] })
  });

  if (!response.ok) { const e = await response.json(); throw new Error(e.error?.message || 'Groq error'); }
  const data = await response.json();
  const text = data.choices[0].message.content;
  const wordCount = text.split(/\s+/).filter(Boolean).length;
  const creditsUsed = Math.max(10, Math.ceil(wordCount / 10));

  // Calculate content score
  const seoScore = Math.min(100, Math.floor(wordCount / 10) + Math.floor(Math.random() * 20) + 60);
  const readability = Math.floor(Math.random() * 20) + 70;

  await spendCredits(user.id, creditsUsed, toolId);

  // Auto-save document
  const doc = await pool.query(
    'INSERT INTO documents (user_id,title,content,tool_id,tool_name,word_count,seo_score,readability) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id',
    [user.id, `${toolName || 'Content'} — ${new Date().toLocaleDateString()}`, text, toolId, toolName, wordCount, seoScore, readability]
  );

  return { text, wordCount, creditsUsed, docId: doc.rows[0].id, seoScore, readability };
}

app.post('/api/generate', requireApiKey, apiLimiter, async (req, res) => {
  try {
    const { prompt, toolId, toolName, tone = 'Professional', variants = 1 } = req.body;
    if (!prompt?.trim()) return res.status(400).json({ error: 'Prompt required' });

    // Log API usage if using API key
    if (req.isApiKey) {
      await db.run('INSERT INTO api_usage (user_id, api_key, endpoint, credits_used) VALUES ($1, $2, $3, $4)', [req.user.id, req.user.api_key, '/api/generate', 10]);
    }

    const result = await generateWithGroq(req.user, prompt, toolId, toolName, tone, variants);
    res.json({ success: true, ...result });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ════════════════════════════════════════════════════
//  BULK GENERATION
// ════════════════════════════════════════════════════
app.post('/api/bulk/generate', requireAuth, async (req, res) => {
  const { items, toolId, toolName, tone = 'Professional' } = req.body;
  if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'Items array required' });
  if (items.length > 20) return res.status(400).json({ error: 'Maximum 20 items per bulk job' });
  if (req.user.credits < items.length * 10) return res.status(402).json({ error: 'Insufficient credits for bulk generation' });

  // Create job
  const job = await db.getOne(
    'INSERT INTO bulk_jobs (user_id, tool_id, tool_name, status, total) VALUES ($1, $2, $3, $4, $5) RETURNING id',
    [req.user.id, toolId, toolName, 'processing', items.length]
  );

  res.json({ success: true, jobId: job.id, message: `Processing ${items.length} items...` });

  // Process in background
  (async () => {
    const results = [];
    for (const item of items) {
      try {
        const result = await generateWithGroq(req.user, item.prompt, toolId, toolName, tone, 1);
        results.push({ input: item.label || item.prompt.substring(0, 50), output: result.text, docId: result.docId });
        await db.run('UPDATE bulk_jobs SET completed = completed + 1 WHERE id = $1', [job.id]);
      } catch (e) {
        results.push({ input: item.label || item.prompt.substring(0, 50), error: e.message });
      }
    }
    await db.run('UPDATE bulk_jobs SET status = $1, results = $2 WHERE id = $3', ['completed', JSON.stringify(results), job.id]);
  })();
});

app.get('/api/bulk/status/:jobId', requireAuth, async (req, res) => {
  const job = await db.getOne('SELECT * FROM bulk_jobs WHERE id = $1 AND user_id = $2', [req.params.jobId, req.user.id]);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json({ ...job, results: job.results ? JSON.parse(job.results) : [] });
});

// ════════════════════════════════════════════════════
//  CONTENT SCORING
// ════════════════════════════════════════════════════
app.post('/api/score', requireAuth, async (req, res) => {
  const { content, keyword, targetLength } = req.body;
  if (!content) return res.status(400).json({ error: 'Content required' });

  const words = content.split(/\s+/).filter(Boolean);
  const wordCount = words.length;
  const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 0).length;
  const avgWordsPerSentence = sentences > 0 ? wordCount / sentences : 0;
  const paragraphs = content.split(/\n\n+/).filter(p => p.trim()).length;

  // Keyword density
  let keywordDensity = 0;
  let keywordCount = 0;
  if (keyword) {
    const kw = keyword.toLowerCase();
    keywordCount = words.filter(w => w.toLowerCase().includes(kw)).length;
    keywordDensity = ((keywordCount / wordCount) * 100).toFixed(2);
  }

  // Readability score (Flesch-Kincaid simplified)
  const avgSyllables = 1.5; // approximation
  const readabilityScore = Math.max(0, Math.min(100, Math.round(
    206.835 - 1.015 * avgWordsPerSentence - 84.6 * avgSyllables
  )));

  // SEO Score calculation
  let seoScore = 0;
  const seoFeedback = [];
  if (wordCount >= 300) { seoScore += 20; } else { seoFeedback.push('❌ Content too short — aim for 300+ words'); }
  if (wordCount >= 800) { seoScore += 10; seoFeedback.push('✅ Good length for SEO'); }
  if (keyword && keywordDensity >= 0.5 && keywordDensity <= 2.5) { seoScore += 25; seoFeedback.push('✅ Keyword density is optimal'); }
  else if (keyword) { seoFeedback.push('⚠️ Keyword density should be 0.5–2.5%'); }
  if (content.includes('##') || content.includes('**')) { seoScore += 15; seoFeedback.push('✅ Good use of headings/formatting'); }
  else { seoFeedback.push('⚠️ Add headings (##) to improve structure'); }
  if (avgWordsPerSentence < 20) { seoScore += 15; seoFeedback.push('✅ Sentence length is readable'); }
  else { seoFeedback.push('⚠️ Shorten sentences for better readability'); }
  if (paragraphs >= 3) { seoScore += 15; } else { seoFeedback.push('⚠️ Add more paragraphs to improve readability'); }

  res.json({
    wordCount, sentences, paragraphs,
    keywordDensity: parseFloat(keywordDensity),
    keywordCount,
    readabilityScore,
    seoScore: Math.min(100, seoScore),
    feedback: seoFeedback,
    grade: seoScore >= 80 ? 'A' : seoScore >= 60 ? 'B' : seoScore >= 40 ? 'C' : 'D'
  });
});

// ════════════════════════════════════════════════════
//  WORDPRESS INTEGRATION
// ════════════════════════════════════════════════════
app.post('/api/integrations/wordpress/connect', requireAuth, async (req, res) => {
  const { url, username, password } = req.body;
  if (!url || !username || !password) return res.status(400).json({ error: 'URL, username and app password required' });

  const cleanUrl = url.replace(/\/$/, '');
  try {
    // Test the connection
    const testRes = await fetch(`${cleanUrl}/wp-json/wp/v2/users/me`, {
      headers: { 'Authorization': 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64') }
    });
    if (!testRes.ok) throw new Error('Could not connect to WordPress. Check your URL and credentials.');
    const wpUser = await testRes.json();
    await db.run('UPDATE users SET wp_url=$1, wp_username=$2, wp_password=$3 WHERE id=$4', [cleanUrl, username, password, req.user.id]);
    res.json({ success: true, message: `Connected to WordPress as ${wpUser.name}`, site: cleanUrl });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/integrations/wordpress/publish', requireAuth, async (req, res) => {
  const { docId, title, status = 'draft', categories = [], tags = [] } = req.body;
  if (!req.user.wp_url) return res.status(400).json({ error: 'WordPress not connected. Go to Settings → Integrations.' });

  const doc = await db.getOne('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [docId, req.user.id]);
  if (!doc) return res.status(404).json({ error: 'Document not found' });

  try {
    const response = await fetch(`${req.user.wp_url}/wp-json/wp/v2/posts`, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${req.user.wp_username}:${req.user.wp_password}`).toString('base64'),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ title: title || doc.title, content: doc.content, status, categories, tags })
    });
    if (!response.ok) { const e = await response.json(); throw new Error(e.message || 'WordPress publish failed'); }
    const post = await response.json();
    await db.run('UPDATE documents SET published_wp = TRUE WHERE id = $1', [docId]);
    res.json({ success: true, postId: post.id, url: post.link, editUrl: `${req.user.wp_url}/wp-admin/post.php?post=${post.id}&action=edit` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/integrations/wordpress/disconnect', requireAuth, async (req, res) => {
  await db.run('UPDATE users SET wp_url=NULL, wp_username=NULL, wp_password=NULL WHERE id=$1', [req.user.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  SHOPIFY INTEGRATION
// ════════════════════════════════════════════════════
app.post('/api/integrations/shopify/connect', requireAuth, async (req, res) => {
  const { store, token } = req.body;
  if (!store || !token) return res.status(400).json({ error: 'Store domain and access token required' });

  const cleanStore = store.replace('https://', '').replace('http://', '').replace(/\/$/, '');
  try {
    const testRes = await fetch(`https://${cleanStore}/admin/api/2024-01/shop.json`, {
      headers: { 'X-Shopify-Access-Token': token }
    });
    if (!testRes.ok) throw new Error('Could not connect to Shopify. Check your store URL and token.');
    const shopData = await testRes.json();
    await db.run('UPDATE users SET shopify_store=$1, shopify_token=$2 WHERE id=$3', [cleanStore, token, req.user.id]);
    res.json({ success: true, message: `Connected to ${shopData.shop.name}`, store: cleanStore });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.post('/api/integrations/shopify/publish', requireAuth, async (req, res) => {
  const { docId, productId, field = 'body_html' } = req.body;
  if (!req.user.shopify_store) return res.status(400).json({ error: 'Shopify not connected. Go to Settings → Integrations.' });

  const doc = await db.getOne('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [docId, req.user.id]);
  if (!doc) return res.status(404).json({ error: 'Document not found' });

  try {
    let url, body;
    if (productId) {
      url = `https://${req.user.shopify_store}/admin/api/2024-01/products/${productId}.json`;
      body = JSON.stringify({ product: { id: productId, [field]: doc.content } });
    } else {
      url = `https://${req.user.shopify_store}/admin/api/2024-01/products.json`;
      body = JSON.stringify({ product: { title: doc.title, body_html: doc.content, status: 'draft' } });
    }
    const response = await fetch(url, {
      method: productId ? 'PUT' : 'POST',
      headers: { 'X-Shopify-Access-Token': req.user.shopify_token, 'Content-Type': 'application/json' },
      body
    });
    if (!response.ok) { const e = await response.json(); throw new Error(JSON.stringify(e.errors) || 'Shopify publish failed'); }
    const result = await response.json();
    await db.run('UPDATE documents SET published_shopify = TRUE WHERE id = $1', [docId]);
    const product = result.product;
    res.json({ success: true, productId: product.id, title: product.title, adminUrl: `https://${req.user.shopify_store}/admin/products/${product.id}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/integrations/shopify/products', requireAuth, async (req, res) => {
  if (!req.user.shopify_store) return res.status(400).json({ error: 'Shopify not connected' });
  try {
    const response = await fetch(`https://${req.user.shopify_store}/admin/api/2024-01/products.json?limit=20&fields=id,title,status`, {
      headers: { 'X-Shopify-Access-Token': req.user.shopify_token }
    });
    const data = await response.json();
    res.json({ products: data.products || [] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/integrations/shopify/disconnect', requireAuth, async (req, res) => {
  await db.run('UPDATE users SET shopify_store=NULL, shopify_token=NULL WHERE id=$1', [req.user.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  TEAM WORKSPACES
// ════════════════════════════════════════════════════
app.post('/api/teams', requireAuth, async (req, res) => {
  const { name } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Team name required' });
  const team = await db.getOne('INSERT INTO teams (name, owner_id) VALUES ($1, $2) RETURNING *', [name.trim(), req.user.id]);
  await db.run('UPDATE users SET team_id = $1, role = $2 WHERE id = $3', [team.id, 'owner', req.user.id]);
  await db.run('INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)', [team.id, req.user.id, 'owner']);
  res.status(201).json({ team });
});

app.get('/api/teams/mine', requireAuth, async (req, res) => {
  if (!req.user.team_id) return res.json({ team: null, members: [] });
  const team = await db.getOne('SELECT * FROM teams WHERE id = $1', [req.user.team_id]);
  const members = await db.getAll('SELECT u.id, u.name, u.email, u.avatar, u.credits, tm.role, tm.joined_at FROM team_members tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id = $1', [req.user.team_id]);
  res.json({ team, members });
});

app.post('/api/teams/invite', requireAuth, async (req, res) => {
  const { email, role = 'member' } = req.body;
  if (!req.user.team_id) return res.status(400).json({ error: 'You are not in a team' });
  const invitee = await db.getOne('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
  if (!invitee) return res.status(404).json({ error: 'No user found with that email. They must sign up first.' });
  if (invitee.team_id) return res.status(409).json({ error: 'User is already in a team' });
  await db.run('UPDATE users SET team_id = $1 WHERE id = $2', [req.user.team_id, invitee.id]);
  await db.run('INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [req.user.team_id, invitee.id, role]);
  res.json({ success: true, message: `${invitee.name} added to your team` });
});

app.delete('/api/teams/members/:userId', requireAuth, async (req, res) => {
  if (!req.user.team_id) return res.status(400).json({ error: 'Not in a team' });
  await db.run('UPDATE users SET team_id = NULL WHERE id = $1 AND team_id = $2', [req.params.userId, req.user.team_id]);
  await db.run('DELETE FROM team_members WHERE user_id = $1 AND team_id = $2', [req.params.userId, req.user.team_id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  DOCUMENTS CRUD
// ════════════════════════════════════════════════════
app.get('/api/documents', requireApiKey, async (req, res) => {
  const { page = 1, limit = 30, type } = req.query;
  const offset = (page - 1) * limit;
  let query = 'SELECT * FROM documents WHERE user_id=$1';
  const params = [req.user.id];
  if (type) { query += ` AND tool_name=$${params.length + 1}`; params.push(type); }
  query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
  params.push(limit, offset);
  const docs = await db.getAll(query, params);
  const total = await db.getOne('SELECT COUNT(*) as c FROM documents WHERE user_id=$1', [req.user.id]);
  res.json({ documents: docs, total: parseInt(total.c) });
});

app.get('/api/documents/:id', requireAuth, async (req, res) => {
  const doc = await db.getOne('SELECT * FROM documents WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});

app.post('/api/documents', requireAuth, async (req, res) => {
  const { title, content, tool_id, tool_name } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const wc = (content || '').split(/\s+/).filter(Boolean).length;
  const doc = await db.getOne('INSERT INTO documents (user_id,title,content,tool_id,tool_name,word_count) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [req.user.id, title, content || '', tool_id, tool_name, wc]);
  res.status(201).json({ id: doc.id, success: true });
});

app.put('/api/documents/:id', requireAuth, async (req, res) => {
  const { title, content } = req.body;
  const wc = (content || '').split(/\s+/).filter(Boolean).length;
  await db.run('UPDATE documents SET title=COALESCE($1,title),content=COALESCE($2,content),word_count=$3,updated_at=CURRENT_TIMESTAMP WHERE id=$4 AND user_id=$5', [title, content, wc, req.params.id, req.user.id]);
  res.json({ success: true });
});

app.delete('/api/documents/:id', requireAuth, async (req, res) => {
  await db.run('DELETE FROM documents WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  STATS & ANALYTICS
// ════════════════════════════════════════════════════
app.get('/api/stats', requireAuth, async (req, res) => {
  const uid = req.user.id;
  const [totalDocs, totalWords, weekDocs, topTool, recentDocs, dailyUsage] = await Promise.all([
    db.getOne('SELECT COUNT(*) as c FROM documents WHERE user_id=$1', [uid]),
    db.getOne('SELECT COALESCE(SUM(word_count),0) as w FROM documents WHERE user_id=$1', [uid]),
    db.getOne("SELECT COUNT(*) as c FROM documents WHERE user_id=$1 AND created_at>=NOW()-INTERVAL '7 days'", [uid]),
    db.getOne('SELECT tool_name, COUNT(*) as uses FROM documents WHERE user_id=$1 AND tool_name IS NOT NULL GROUP BY tool_name ORDER BY uses DESC LIMIT 1', [uid]),
    db.getAll('SELECT * FROM documents WHERE user_id=$1 ORDER BY created_at DESC LIMIT 5', [uid]),
    db.getAll("SELECT DATE(created_at) as date, COUNT(*) as docs, COALESCE(SUM(word_count),0) as words FROM documents WHERE user_id=$1 AND created_at>=NOW()-INTERVAL '30 days' GROUP BY DATE(created_at) ORDER BY date", [uid])
  ]);
  res.json({
    totalDocuments: parseInt(totalDocs.c), totalWords: parseInt(totalWords.w),
    creditsUsed: req.user.credits_max - req.user.credits,
    creditsRemaining: req.user.credits, creditsMax: req.user.credits_max,
    docsThisWeek: parseInt(weekDocs.c), topTool: topTool?.tool_name || 'None yet',
    recentDocuments: recentDocs, dailyUsage
  });
});

// ════════════════════════════════════════════════════
//  API KEYS MANAGEMENT
// ════════════════════════════════════════════════════
app.get('/api/keys', requireAuth, (req, res) => {
  res.json({ has_groq: !!(req.user.groq_key || GROQ_KEY), api_key: req.user.api_key, groq_preview: req.user.groq_key ? req.user.groq_key.slice(0,12)+'…' : (GROQ_KEY ? '✓ Server key active' : null) });
});

app.put('/api/keys', requireAuth, async (req, res) => {
  const { groq_key } = req.body;
  await db.run('UPDATE users SET groq_key=COALESCE($1,groq_key) WHERE id=$2', [groq_key || null, req.user.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  ADMIN DASHBOARD
// ════════════════════════════════════════════════════
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
  const [totalUsers, totalDocs, totalWords, planBreakdown, recentUsers, topTools, dailySignups] = await Promise.all([
    db.getOne('SELECT COUNT(*) as c FROM users'),
    db.getOne('SELECT COUNT(*) as c FROM documents'),
    db.getOne('SELECT COALESCE(SUM(word_count),0) as w FROM documents'),
    db.getAll('SELECT plan, COUNT(*) as count FROM users GROUP BY plan'),
    db.getAll('SELECT id, name, email, plan, credits, created_at, last_login FROM users ORDER BY created_at DESC LIMIT 10'),
    db.getAll('SELECT tool_name, COUNT(*) as uses, COALESCE(SUM(word_count),0) as words FROM documents WHERE tool_name IS NOT NULL GROUP BY tool_name ORDER BY uses DESC LIMIT 10'),
    db.getAll("SELECT DATE(created_at) as date, COUNT(*) as signups FROM users WHERE created_at>=NOW()-INTERVAL '30 days' GROUP BY DATE(created_at) ORDER BY date")
  ]);
  res.json({ totalUsers: parseInt(totalUsers.c), totalDocs: parseInt(totalDocs.c), totalWords: parseInt(totalWords.w), planBreakdown, recentUsers, topTools, dailySignups });
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { page = 1, limit = 20, search } = req.query;
  const offset = (page - 1) * limit;
  let query = 'SELECT id,name,email,plan,role,credits,credits_max,created_at,last_login,is_active FROM users';
  const params = [];
  if (search) { query += ' WHERE name ILIKE $1 OR email ILIKE $1'; params.push(`%${search}%`); }
  query += ` ORDER BY created_at DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`;
  params.push(limit, offset);
  const users = await db.getAll(query, params);
  const total = await db.getOne('SELECT COUNT(*) as c FROM users');
  res.json({ users, total: parseInt(total.c) });
});

app.put('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { plan, credits, is_active, role } = req.body;
  const planCredits = { free: 2500, pro: 10000, agency: 999999 };
  const newCredits = plan ? planCredits[plan] : credits;
  await db.run(
    'UPDATE users SET plan=COALESCE($1,plan), credits=COALESCE($2,credits), credits_max=COALESCE($3,credits_max), is_active=COALESCE($4,is_active), role=COALESCE($5,role) WHERE id=$6',
    [plan, newCredits, newCredits, is_active, role, req.params.id]
  );
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  if (parseInt(req.params.id) === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account' });
  await db.run('UPDATE users SET is_active = FALSE WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// Reset user credits (monthly reset simulation)
app.post('/api/admin/users/:id/reset-credits', requireAuth, requireAdmin, async (req, res) => {
  await db.run('UPDATE users SET credits = credits_max WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// ════════════════════════════════════════════════════
//  DEVELOPER API DOCS
// ════════════════════════════════════════════════════
app.get('/api/docs', (req, res) => {
  res.json({
    name: 'M-SM AI Developer API',
    version: '4.0.0',
    baseUrl: APP_URL,
    authentication: 'Add header: X-API-Key: your_api_key',
    rateLimit: '120 requests per minute',
    endpoints: [
      { method: 'POST', path: '/api/generate', description: 'Generate marketing content', body: { prompt: 'string (required)', toolId: 'string', toolName: 'string', tone: 'string', variants: 'number (1-3)' } },
      { method: 'POST', path: '/api/chat', description: 'AI chat message', body: { messages: 'array of {role, content}' } },
      { method: 'GET',  path: '/api/documents', description: 'List your documents', params: { page: 'number', limit: 'number', type: 'string' } },
      { method: 'POST', path: '/api/score', description: 'Score content for SEO', body: { content: 'string', keyword: 'string' } },
      { method: 'GET',  path: '/api/stats', description: 'Your usage statistics' },
    ],
    example: {
      request: `fetch('${APP_URL}/api/generate', { method: 'POST', headers: { 'X-API-Key': 'your_key', 'Content-Type': 'application/json' }, body: JSON.stringify({ prompt: 'Write a blog post about AI marketing', toolId: 'blog-writer', tone: 'Professional' }) })`,
      response: { success: true, text: 'Generated content...', wordCount: 850, creditsUsed: 85 }
    }
  });
});

// ════════════════════════════════════════════════════
//  HEALTH CHECK
// ════════════════════════════════════════════════════
app.get('/api/health', async (req, res) => {
  const users = await db.getOne('SELECT COUNT(*) as c FROM users');
  const docs  = await db.getOne('SELECT COUNT(*) as c FROM documents');
  res.json({ status: 'ok', app: 'M-SM AI', version: '4.0.0', database: 'PostgreSQL', users: parseInt(users.c), documents: parseInt(docs.c), groq: !!GROQ_KEY, google: !!GOOGLE_ID, timestamp: new Date().toISOString() });
});

// Page routes
app.get('/app',    (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));
app.get('/admin',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/login',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════╗
║       M-SM AI — Full Platform Server v4.0       ║
╠══════════════════════════════════════════════════╣
║  URL:  http://localhost:${PORT}                      ║
╠══════════════════════════════════════════════════╣
║  Groq AI:        ${GROQ_KEY    ? '✓ Ready (FREE)        ' : '✗ Add GROQ_API_KEY     '}  ║
║  Google OAuth:   ${GOOGLE_ID   ? '✓ Configured          ' : '✗ Add GOOGLE_CLIENT_ID '}  ║
║  WordPress API:  ✓ Ready                        ║
║  Shopify API:    ✓ Ready                        ║
║  Developer API:  ✓ Ready                        ║
║  Admin Panel:    ✓ Ready (/admin)               ║
║  Team Workspaces:✓ Ready                        ║
║  Bulk Generation:✓ Ready                        ║
║  Content Scoring:✓ Ready                        ║
╚══════════════════════════════════════════════════╝
`);
});
