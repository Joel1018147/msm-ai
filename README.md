# M-SM AI v2.0 — Complete SaaS Platform
### Full-stack AI Marketing System with Auth, Database & Groq AI

---

## 📁 Project Structure

```
msm-ai/
├── public/
│   ├── index.html      ← Landing page (marketing website)
│   ├── login.html      ← Login page
│   ├── signup.html     ← Signup page  
│   └── app.html        ← Main dashboard (after login)
├── server.js           ← Express backend + all API routes
├── package.json        ← Dependencies
├── .env.example        ← Environment variables template
└── README.md           ← This file
```

---

## 🚀 Quick Start (5 Minutes)

### Step 1 — Install dependencies
```bash
npm install
```

### Step 2 — Set up environment variables
```bash
cp .env.example .env
```
Open `.env` and fill in:
- `JWT_SECRET` — any long random string (keep secret!)
- `GROQ_API_KEY` — free at console.groq.com (powers AI Chat)
- `ANTHROPIC_API_KEY` — from console.anthropic.com (powers content tools)

### Step 3 — Start the server
```bash
npm start
```

### Step 4 — Open your browser
```
http://localhost:3000
```

That's it! The SQLite database is created automatically on first run.

---

## 🔑 Getting Your API Keys

### Groq API Key (FREE — for AI Chat)
1. Go to **console.groq.com**
2. Create account → Click "API Keys" → "Create API Key"
3. Copy key (starts with `gsk_`)
4. Paste into `.env` as `GROQ_API_KEY`

**Groq is completely free** — no billing required. It uses LLaMA 3 and responds in under 1 second.

### Anthropic API Key (for content generation tools)
1. Go to **console.anthropic.com**
2. Sign up → Billing → Add payment method
3. API Keys → Create Key
4. Paste into `.env` as `ANTHROPIC_API_KEY`

**Note:** Users can also add their own keys in Settings → API Keys inside the app.

---

## 🌐 Deploying to a Live Website

### Option 1: Railway (EASIEST — recommended for beginners)
```
1. Go to railway.app → Sign up with GitHub
2. New Project → Deploy from GitHub Repo
3. Upload your code to GitHub first:
   git init
   git add .
   git commit -m "M-SM AI v2"
   git remote add origin https://github.com/YOUR_USERNAME/msm-ai.git
   git push -u origin main
4. In Railway: New Project → Deploy from GitHub → Select your repo
5. Variables tab → Add all variables from .env
6. Railway gives you a URL like: https://msm-ai-production.up.railway.app
```
**Cost: Free tier available, ~$5/month for always-on**

### Option 2: Render
```
1. Go to render.com → New → Web Service
2. Connect GitHub repo
3. Build Command: npm install
4. Start Command: node server.js
5. Add environment variables
6. Deploy → Get URL like: https://msm-ai.onrender.com
```
**Cost: Free tier (sleeps after 15min inactivity), $7/month for always-on**

### Option 3: VPS + Custom Domain (PROFESSIONAL)

**Recommended VPS providers:**
- DigitalOcean: $6/month (1GB RAM Droplet)
- Hetzner: $4/month (best value)
- Vultr: $6/month

```bash
# 1. Create Ubuntu 22.04 VPS, SSH in
ssh root@YOUR_SERVER_IP

# 2. Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs git nginx certbot python3-certbot-nginx

# 3. Clone your code
git clone https://github.com/YOUR_USERNAME/msm-ai.git /var/www/msm-ai
cd /var/www/msm-ai
npm install --production

# 4. Set up environment
cp .env.example .env
nano .env   # Fill in your keys

# 5. Install PM2 (keeps server running)
npm install -g pm2
pm2 start server.js --name msm-ai
pm2 startup
pm2 save

# 6. Set up Nginx
nano /etc/nginx/sites-available/msm-ai
```

**Nginx config:**
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/msm-ai /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# 7. Free SSL certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Your site will be live at **https://yourdomain.com**

### Option 4: Docker
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

```bash
docker build -t msm-ai .
docker run -d -p 3000:3000 \
  -e JWT_SECRET=your_secret \
  -e GROQ_API_KEY=gsk_... \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  -v $(pwd)/msm-ai.db:/app/msm-ai.db \
  msm-ai
```

---

## 🔗 Getting a Domain Name

1. Go to **Namecheap.com** or **GoDaddy.com**
2. Search for a domain (e.g. `msm-ai.com`)
3. Purchase (~$10-15/year)
4. In DNS settings, add an **A Record**:
   - Host: `@` and `www`
   - Value: Your server's IP address
5. Wait 5-30 minutes for DNS to propagate
6. Run Certbot on your VPS for free HTTPS

---

## 📊 Database

The app uses **SQLite** by default — zero configuration needed, data saved to `msm-ai.db`.

**Tables:**
- `users` — accounts, plans, credits, brand voice settings
- `documents` — all generated content
- `usage_log` — credit usage tracking
- `sessions` — auth session tracking

**Upgrading to PostgreSQL** (for large scale):
```bash
npm install pg
# Update DB_PATH in .env to use DATABASE_URL
# Change better-sqlite3 calls to pg queries in server.js
```

---

## 💰 Monetizing (Stripe Payments)

To accept real payments:

```bash
npm install stripe
```

Add to `.env`:
```
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRO_PRICE_ID=price_...
STRIPE_AGENCY_PRICE_ID=price_...
```

Add to `server.js`:
```javascript
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post('/api/billing/checkout', requireAuth, async (req, res) => {
  const { plan } = req.body;
  const priceId = plan === 'pro' ? process.env.STRIPE_PRO_PRICE_ID : process.env.STRIPE_AGENCY_PRICE_ID;
  
  const session = await stripe.checkout.sessions.create({
    customer_email: req.user.email,
    line_items: [{ price: priceId, quantity: 1 }],
    mode: 'subscription',
    success_url: `${process.env.APP_URL}/app.html?upgraded=true`,
    cancel_url: `${process.env.APP_URL}/app.html`,
  });
  
  res.json({ url: session.url });
});
```

---

## 🔒 Security Checklist

- [x] Passwords hashed with bcrypt (12 rounds)
- [x] JWT tokens (7-day expiry)
- [x] Rate limiting on auth + API routes
- [x] Helmet.js security headers
- [x] SQL injection protected (parameterized queries)
- [x] CORS configured
- [ ] Change JWT_SECRET to strong random value
- [ ] Set NODE_ENV=production
- [ ] Enable HTTPS with Certbot
- [ ] Set ALLOWED_ORIGIN to your domain

---

## 📡 API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/register` | No | Create account |
| POST | `/api/auth/login` | No | Sign in |
| GET | `/api/auth/me` | Yes | Get current user |
| PUT | `/api/auth/me` | Yes | Update profile |
| POST | `/api/chat` | Yes | AI Chat (Groq) |
| POST | `/api/generate` | Yes | Generate content |
| GET | `/api/documents` | Yes | List documents |
| POST | `/api/documents` | Yes | Save document |
| PUT | `/api/documents/:id` | Yes | Update document |
| DELETE | `/api/documents/:id` | Yes | Delete document |
| GET | `/api/stats` | Yes | Dashboard stats |
| PUT | `/api/keys` | Yes | Save API keys |
| GET | `/api/health` | No | Health check |

---

## 🤝 Selling to Clients

### White-labeling
1. Replace "M-SM AI" with client's brand name in all HTML files
2. Update colors in CSS `:root` variables
3. Change logo letter "M" to client's initial
4. Deploy to client's domain

### Reseller model
- You host one instance per client
- Charge $50-200/month per client
- Your cost: ~$10/month server + API usage
- Profit: $40-190/month per client

### Cost estimate per client (Pro plan at $49/mo)
- Server cost: ~$5/month (shared VPS)
- API costs: ~$8-15/month (typical usage)
- Your profit: ~$29-36/month per client

---

M-SM AI v2.0 · Built with Node.js, Express, SQLite, Groq AI & Anthropic Claude
