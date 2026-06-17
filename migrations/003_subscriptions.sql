-- Migration 003: Subscription infrastructure
-- Tables: subscriptions, payments, invoices
-- Safe to re-run: all DDL uses IF NOT EXISTS / IF NOT EXISTS guards

-- ── Subscriptions ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS subscriptions (
  id                     SERIAL PRIMARY KEY,
  user_id                INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plan                   VARCHAR(50)  NOT NULL DEFAULT 'trial',
  billing_cycle          VARCHAR(20)  NOT NULL DEFAULT 'yearly',
  status                 VARCHAR(50)  NOT NULL DEFAULT 'trial',
  trial_starts_at        TIMESTAMPTZ  DEFAULT NOW(),
  trial_ends_at          TIMESTAMPTZ  DEFAULT (NOW() + INTERVAL '30 days'),
  paid_until             TIMESTAMPTZ,
  grace_until            TIMESTAMPTZ,
  ipay88_subscription_no VARCHAR(255),
  amount_paid            DECIMAL(10,2),
  currency               VARCHAR(10)  NOT NULL DEFAULT 'MYR',
  created_at             TIMESTAMPTZ  DEFAULT NOW(),
  updated_at             TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE(user_id)
);

-- ── Payments ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS payments (
  id                     SERIAL PRIMARY KEY,
  user_id                INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subscription_id        INTEGER REFERENCES subscriptions(id) ON DELETE SET NULL,
  ipay88_ref_no          VARCHAR(255),
  ipay88_transaction_id  VARCHAR(255),
  amount                 DECIMAL(10,2) NOT NULL,
  currency               VARCHAR(10)  NOT NULL DEFAULT 'MYR',
  payment_method         VARCHAR(100),
  status                 VARCHAR(50)  NOT NULL DEFAULT 'pending',
  billing_cycle          VARCHAR(20),
  ipay88_response        JSONB,
  paid_at                TIMESTAMPTZ,
  created_at             TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Invoices ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS invoices (
  id             SERIAL PRIMARY KEY,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  payment_id     INTEGER REFERENCES payments(id) ON DELETE SET NULL,
  invoice_number VARCHAR(100) UNIQUE NOT NULL,
  business_name  VARCHAR(255),
  business_email VARCHAR(255),
  amount         DECIMAL(10,2) NOT NULL,
  tax_amount     DECIMAL(10,2) NOT NULL DEFAULT 0,
  total_amount   DECIMAL(10,2) NOT NULL,
  billing_cycle  VARCHAR(20),
  period_start   DATE,
  period_end     DATE,
  status         VARCHAR(50)  NOT NULL DEFAULT 'issued',
  pdf_url        TEXT,
  created_at     TIMESTAMPTZ  DEFAULT NOW()
);

-- ── Seed: trial subscription for every existing user without one ───────────────

INSERT INTO subscriptions (user_id, plan, billing_cycle, status, trial_starts_at, trial_ends_at)
SELECT id, 'trial', 'yearly', 'trial', NOW(), NOW() + INTERVAL '30 days'
FROM users
WHERE id NOT IN (SELECT user_id FROM subscriptions)
ON CONFLICT (user_id) DO NOTHING;

-- ── Indexes ────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_subscriptions_user   ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_payments_user        ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_invoices_user        ON invoices(user_id);

-- ── Reminder tracking ──────────────────────────────────────────────────────────

ALTER TABLE subscriptions
ADD COLUMN IF NOT EXISTS reminder_sent JSONB DEFAULT '{}';
