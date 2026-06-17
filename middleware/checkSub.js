'use strict';

const { pool } = require('../db');

async function checkSub(req, res, next) {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM subscriptions WHERE user_id = $1',
      [req.user.id]
    );

    let sub = rows[0];

    // Auto-provision a trial row if none exists
    if (!sub) {
      const inserted = await pool.query(
        `INSERT INTO subscriptions (user_id, plan, billing_cycle, status, trial_starts_at, trial_ends_at)
         VALUES ($1, 'trial', 'yearly', 'trial', NOW(), NOW() + INTERVAL '30 days')
         ON CONFLICT (user_id) DO NOTHING
         RETURNING *`,
        [req.user.id]
      );
      sub = inserted.rows[0];
      if (!sub) {
        // Concurrent insert won — fetch the committed row
        const refetch = await pool.query(
          'SELECT * FROM subscriptions WHERE user_id = $1',
          [req.user.id]
        );
        sub = refetch.rows[0];
      }
    }

    // Fail open — should never happen but don't block the user
    if (!sub) return next();

    const now = Date.now();

    // ── ACTIVE ──────────────────────────────────────────────────────────────────
    if (sub.status === 'active' && new Date(sub.paid_until) > now) {
      req.subscription = { status: 'active', paid_until: sub.paid_until, showBanner: false };
      return next();
    }

    // ── TRIAL ACTIVE ─────────────────────────────────────────────────────────────
    if (sub.status === 'trial' && new Date(sub.trial_ends_at) > now) {
      const daysLeft = Math.ceil((new Date(sub.trial_ends_at) - now) / 86400000);
      req.subscription = { status: 'trial', daysLeft, showBanner: daysLeft <= 7 };
      if (req.subscription.showBanner) {
        req.subscription.bannerType    = 'warning';
        req.subscription.bannerMessage = `Your free trial ends in ${daysLeft} day(s). Upgrade now to keep access.`;
      }
      return next();
    }

    // ── GRACE ────────────────────────────────────────────────────────────────────
    if (sub.status === 'grace' && new Date(sub.grace_until) > now) {
      const daysLeft = Math.ceil((new Date(sub.grace_until) - now) / 86400000);
      req.subscription = {
        status:        'grace',
        daysLeft,
        showBanner:    true,
        bannerType:    'error',
        bannerMessage: `Your subscription has expired. Renew within ${daysLeft} day(s) or your account will be locked.`,
      };
      return next();
    }

    // ── HARD LOCKED (expired or grace elapsed) ───────────────────────────────────
    if (req.accepts('json') || req.xhr) {
      return res.status(402).json({
        error:    'subscription_expired',
        message:  'Your subscription has expired. Please renew at /billing.',
        redirect: '/billing',
      });
    }
    return res.redirect('/billing?expired=true');

  } catch (err) {
    console.error('checkSub error:', err.message);
    next(); // Never block the user due to a subscription lookup failure
  }
}

async function updateExpiredSubscriptions(pool) {
  // trial → grace
  await pool.query(`
    UPDATE subscriptions
       SET status      = 'grace',
           grace_until = trial_ends_at + INTERVAL '3 days',
           updated_at  = NOW()
     WHERE status = 'trial'
       AND trial_ends_at < NOW()
  `);

  // active → grace
  await pool.query(`
    UPDATE subscriptions
       SET status      = 'grace',
           grace_until = paid_until + INTERVAL '3 days',
           updated_at  = NOW()
     WHERE status = 'active'
       AND paid_until < NOW()
  `);

  // grace → expired
  await pool.query(`
    UPDATE subscriptions
       SET status     = 'expired',
           updated_at = NOW()
     WHERE status = 'grace'
       AND grace_until < NOW()
  `);
}

async function sendTrialReminders(pool) {
  const { sendTrialReminder } = require('../routes/subscription');

  const thresholds = [
    { days: 7, key: 'day7' },
    { days: 3, key: 'day3' },
    { days: 1, key: 'day1' },
  ];

  for (const { days, key } of thresholds) {
    try {
      const result = await pool.query(`
        SELECT s.user_id, s.reminder_sent, u.name, u.email
        FROM subscriptions s
        JOIN users u ON u.id = s.user_id
        WHERE s.status = 'trial'
          AND s.trial_ends_at > NOW() + INTERVAL '${days - 1} days'
          AND s.trial_ends_at <= NOW() + INTERVAL '${days} days'
          AND (s.reminder_sent->>'${key}') IS NULL
      `);

      for (const row of result.rows) {
        await sendTrialReminder({ name: row.name, email: row.email }, days);
        await pool.query(`
          UPDATE subscriptions
             SET reminder_sent = reminder_sent || $1::jsonb,
                 updated_at    = NOW()
           WHERE user_id = $2
        `, [JSON.stringify({ [key]: true }), row.user_id]);
      }

      if (result.rows.length > 0) {
        console.log(`Sent ${result.rows.length} day-${days} trial reminders`);
      }
    } catch (err) {
      console.error(`Trial reminder error (day ${days}):`, err.message);
    }
  }
}

module.exports = { checkSub, updateExpiredSubscriptions, sendTrialReminders };
