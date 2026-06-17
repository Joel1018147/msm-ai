'use strict';

const express = require('express');
const crypto  = require('crypto');
const { pool } = require('../db');
const { Resend } = require('resend');

const router = express.Router();

// ── Constants ─────────────────────────────────────────────────────────────────

const PLANS = {
  monthly: {
    amount:      38.00,
    amountCents: '3800',
    label:       'Monthly Plan',
    prodDesc:    'M-EasyTools AI+ Monthly Subscription',
    days:        30,
  },
  yearly: {
    amount:      365.00,
    amountCents: '36500',
    label:       'Annual Plan',
    prodDesc:    'M-EasyTools AI+ Annual Subscription',
    days:        365,
  },
};

const IPAY88_URL = process.env.IPAY88_SANDBOX === 'true'
  ? 'https://sandbox.ipay88.com.my/ePayment/entry.asp'
  : 'https://payment.ipay88.com.my/ePayment/entry.asp';

// ── Signature helpers ─────────────────────────────────────────────────────────

function generateSignature(merchantKey, merchantCode, refNo, amount, currency) {
  const amountStr = String(Math.round(parseFloat(amount) * 100));
  const raw = merchantKey + merchantCode + refNo + amountStr + currency;
  return crypto.createHash('sha1').update(raw).digest('hex');
}

function verifyBackendSignature(merchantKey, merchantCode, paymentId, refNo, amount, currency, status) {
  const amountStr = String(Math.round(parseFloat(amount) * 100));
  const raw = merchantKey + merchantCode + paymentId + refNo + amountStr + currency + status;
  return crypto.createHash('sha1').update(raw).digest('hex');
}

// ── Invoice number ────────────────────────────────────────────────────────────

async function generateInvoiceNumber(pool) {
  const year   = new Date().getFullYear();
  const result = await pool.query(
    `SELECT COUNT(*) FROM invoices WHERE invoice_number LIKE $1`,
    [`INV-MEASYTOOLS-${year}-%`]
  );
  const seq = parseInt(result.rows[0].count) + 1;
  return `INV-MEASYTOOLS-${year}-${String(seq).padStart(4, '0')}`;
}

// ── Escape helper for HTML output ─────────────────────────────────────────────

function esc(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ── POST /billing/checkout ────────────────────────────────────────────────────
// Registered in server.js with requireAuth + checkSub.

async function checkoutHandler(req, res) {
  try {
    const { billing_cycle } = req.body;

    if (!PLANS[billing_cycle]) {
      return res.status(400).json({ error: 'Invalid billing_cycle. Must be monthly or yearly.' });
    }

    const MERCHANT_CODE = process.env.IPAY88_MERCHANT_CODE;
    const MERCHANT_KEY  = process.env.IPAY88_MERCHANT_KEY;
    if (!MERCHANT_CODE || !MERCHANT_KEY) {
      return res.status(500).json({ error: 'Payment gateway not configured.' });
    }

    const plan    = PLANS[billing_cycle];
    const APP_URL = process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
    const refNo   = `MEASYTOOLS-${req.user.id}-${Date.now()}`;

    // Insert pending payment, linking to subscription via subquery
    const { rows } = await pool.query(
      `INSERT INTO payments
         (user_id, subscription_id, ipay88_ref_no, amount, currency, billing_cycle, status)
       SELECT $1, s.id, $2, $3, 'MYR', $4, 'pending'
       FROM subscriptions s WHERE s.user_id = $1
       RETURNING id`,
      [req.user.id, refNo, plan.amount, billing_cycle]
    );

    if (!rows.length) {
      return res.status(500).json({ error: 'Could not create payment record.' });
    }

    const signature   = generateSignature(MERCHANT_KEY, MERCHANT_CODE, refNo, plan.amount, 'MYR');
    const responseURL = `${APP_URL}/payment/response`;
    const backendURL  = `${APP_URL}/payment/backend`;

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Redirecting to Payment…</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0d14;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .wrap{text-align:center;padding:40px}
  .spinner{width:48px;height:48px;border:4px solid rgba(255,255,255,0.1);border-top-color:#1a73e8;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 24px}
  @keyframes spin{to{transform:rotate(360deg)}}
  h2{font-size:20px;font-weight:700;margin-bottom:8px}
  p{color:#94a3b8;font-size:14px}
</style>
</head>
<body>
<div class="wrap">
  <div class="spinner"></div>
  <h2>Redirecting to payment…</h2>
  <p>Please do not close this window.</p>
</div>
<form id="ipay88" method="POST" action="${esc(IPAY88_URL)}">
  <input type="hidden" name="MerchantCode" value="${esc(MERCHANT_CODE)}">
  <input type="hidden" name="RefNo"        value="${esc(refNo)}">
  <input type="hidden" name="Amount"       value="${plan.amount.toFixed(2)}">
  <input type="hidden" name="Currency"     value="MYR">
  <input type="hidden" name="ProdDesc"     value="${esc(plan.prodDesc)}">
  <input type="hidden" name="UserName"     value="${esc(req.user.name)}">
  <input type="hidden" name="UserEmail"    value="${esc(req.user.email)}">
  <input type="hidden" name="UserContact"  value="">
  <input type="hidden" name="Remark"       value="">
  <input type="hidden" name="Lang"         value="UTF-8">
  <input type="hidden" name="Signature"    value="${esc(signature)}">
  <input type="hidden" name="ResponseURL"  value="${esc(responseURL)}">
  <input type="hidden" name="BackendURL"   value="${esc(backendURL)}">
</form>
<script>document.getElementById('ipay88').submit();</script>
</body>
</html>`);

  } catch (err) {
    console.error('checkout error:', err);
    res.status(500).json({ error: 'Payment initiation failed.' });
  }
}

// ── GET /api/subscription/status ─────────────────────────────────────────────
// Registered in server.js with requireAuth + checkSub.
// req.subscription is already populated by checkSub — fetch the remaining
// plan/billing_cycle fields and merge.

async function statusHandler(req, res) {
  try {
    const { rows } = await pool.query(
      `SELECT status, plan, billing_cycle, trial_ends_at, paid_until, grace_until
       FROM subscriptions WHERE user_id = $1`,
      [req.user.id]
    );
    const row = rows[0] || {};
    const sub = req.subscription || {};

    res.json({
      status:        row.status        ?? sub.status  ?? null,
      plan:          row.plan          ?? null,
      billing_cycle: row.billing_cycle ?? null,
      daysLeft:      sub.daysLeft      ?? null,
      trial_ends_at: row.trial_ends_at ?? null,
      paid_until:    row.paid_until    ?? null,
      grace_until:   row.grace_until   ?? null,
      showBanner:    sub.showBanner    ?? false,
      bannerType:    sub.bannerType    ?? null,
      bannerMessage: sub.bannerMessage ?? null,
    });
  } catch (err) {
    console.error('subscription status error:', err);
    res.status(500).json({ error: 'Could not fetch subscription status.' });
  }
}

// ── POST /payment/response ────────────────────────────────────────────────────
// iPay88 redirects the customer's browser here — no auth, read-only redirect.

router.post('/payment/response', (req, res) => {
  const { Status } = req.body;
  if (Status === '1') return res.redirect('/billing?success=true');
  return res.redirect('/billing?failed=true');
});

// ── POST /payment/backend ─────────────────────────────────────────────────────
// iPay88 server-to-server callback — no session, must always respond '1'.

router.post('/payment/backend', async (req, res) => {
  const respond = () => res.set('Content-Type', 'text/plain').send('1');

  const {
    MerchantCode, PaymentId, RefNo, Amount, Currency,
    TransactionId, Status, Signature,
  } = req.body;

  const MERCHANT_CODE = process.env.IPAY88_MERCHANT_CODE;
  const MERCHANT_KEY  = process.env.IPAY88_MERCHANT_KEY;

  // Step 1: Verify signature
  const expected = verifyBackendSignature(
    MERCHANT_KEY, MERCHANT_CODE, PaymentId, RefNo, Amount, Currency, Status
  );
  if (Signature !== expected) {
    console.warn(`iPay88 backend: signature mismatch for RefNo=${RefNo}`);
    return respond();
  }

  // Step 2: Find payment + user by RefNo
  let payment;
  try {
    const { rows } = await pool.query(
      `SELECT p.*, u.name AS user_name, u.email AS user_email
       FROM payments p
       JOIN users u ON u.id = p.user_id
       WHERE p.ipay88_ref_no = $1`,
      [RefNo]
    );
    payment = rows[0];
  } catch (err) {
    console.error('iPay88 backend: payment lookup failed:', err.message);
    return respond();
  }

  if (!payment) {
    console.warn(`iPay88 backend: no payment found for RefNo=${RefNo}`);
    return respond();
  }

  const ipay88Response = JSON.stringify(req.body);

  if (Status === '1') {
    // Step 3: Success path — activate subscription, create invoice, send email
    try {
      // 3a: Mark payment successful
      await pool.query(
        `UPDATE payments
            SET status                = 'success',
                ipay88_transaction_id = $1,
                ipay88_response       = $2::jsonb,
                paid_at               = NOW()
          WHERE id = $3`,
        [TransactionId, ipay88Response, payment.id]
      );

      // 3b-d: Activate subscription with correct interval
      const intervalDays = payment.billing_cycle === 'monthly' ? 30 : 365;
      await pool.query(
        `UPDATE subscriptions
            SET status                 = 'active',
                paid_until             = NOW() + make_interval(days => $1),
                plan                   = $2,
                billing_cycle          = $2,
                ipay88_subscription_no = $3,
                updated_at             = NOW()
          WHERE user_id = $4`,
        [intervalDays, payment.billing_cycle, TransactionId, payment.user_id]
      );

      // Fetch paid_until for invoice + email
      const { rows: subRows } = await pool.query(
        `SELECT paid_until FROM subscriptions WHERE user_id = $1`,
        [payment.user_id]
      );
      const paidUntil = subRows[0]?.paid_until;

      // 3e-g: Create invoice — wrap separately so failure doesn't block '1' response
      try {
        const invoiceNumber = await generateInvoiceNumber(pool);
        const periodEnd     = paidUntil
          ? new Date(paidUntil).toISOString().split('T')[0]
          : null;

        await pool.query(
          `INSERT INTO invoices
             (user_id, payment_id, invoice_number, business_name, business_email,
              amount, tax_amount, total_amount, billing_cycle,
              period_start, period_end, status)
           VALUES ($1, $2, $3, $4, $5, $6, 0, $6, $7, NOW()::date, $8, 'issued')`,
          [
            payment.user_id, payment.id, invoiceNumber,
            payment.user_name, payment.user_email,
            payment.amount, payment.billing_cycle, periodEnd,
          ]
        );

        // 3h: Confirmation email
        if (process.env.RESEND_API_KEY && payment.user_email) {
          try {
            const resend    = new Resend(process.env.RESEND_API_KEY);
            const fromRaw   = process.env.EMAIL_FROM || 'noreply@modusaiassociates.com';
            const from      = fromRaw.includes('<') ? fromRaw : `M-EasyTools AI+ <${fromRaw}>`;
            const plan      = PLANS[payment.billing_cycle] || PLANS.monthly;
            const APP_URL   = process.env.APP_URL || 'https://app.measytools.com';
            const validUntilFormatted = paidUntil
              ? new Date(paidUntil).toLocaleDateString('en-GB', {
                  day: '2-digit', month: 'short', year: 'numeric',
                })
              : 'N/A';
            const amountFormatted = `RM ${parseFloat(payment.amount).toFixed(2)}`;

            await resend.emails.send({
              from,
              to:      payment.user_email,
              subject: 'Your M-EasyTools AI+ subscription is active 🎉',
              html: `
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:520px;margin:40px auto;background:#fff;border-radius:12px;padding:36px;border:1px solid #e5e7eb">
  <div style="margin-bottom:24px">
    <div style="background:#1a73e8;border-radius:8px;display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;font-size:18px">🛠️</div>
    <strong style="font-size:17px;color:#0d1b2a;vertical-align:middle;margin-left:10px">M-EasyTools AI+</strong>
  </div>
  <h2 style="color:#0d1b2a;font-size:22px;margin:0 0 8px">Your subscription is active!</h2>
  <p style="color:#6b7a8d;font-size:14px;margin:0 0 28px;line-height:1.6">Thank you for subscribing to M-EasyTools AI+. Here are your subscription details.</p>
  <div style="background:#f8faff;border-radius:10px;padding:20px;margin-bottom:24px">
    <table style="width:100%;border-collapse:collapse;font-size:14px">
      <tr><td style="color:#6b7a8d;padding:7px 0">Invoice Number</td><td style="color:#0d1b2a;font-weight:600;text-align:right">${invoiceNumber}</td></tr>
      <tr><td style="color:#6b7a8d;padding:7px 0">Plan</td>          <td style="color:#0d1b2a;font-weight:600;text-align:right">${plan.label}</td></tr>
      <tr><td style="color:#6b7a8d;padding:7px 0">Amount</td>        <td style="color:#0d1b2a;font-weight:600;text-align:right">${amountFormatted}</td></tr>
      <tr><td style="color:#6b7a8d;padding:7px 0">Valid Until</td>   <td style="color:#0d1b2a;font-weight:600;text-align:right">${validUntilFormatted}</td></tr>
    </table>
  </div>
  <a href="${APP_URL}/billing" style="display:block;background:#1a73e8;color:#fff;text-decoration:none;padding:13px 24px;border-radius:8px;font-size:14px;font-weight:700;text-align:center;margin-bottom:24px">View Invoice &amp; Billing History →</a>
  <p style="color:#9ca3af;font-size:12px;margin:0;line-height:1.7">Questions? Contact us at <a href="mailto:info@modusaiassociates.com" style="color:#1a73e8">info@modusaiassociates.com</a></p>
</div>`.trim(),
            });
          } catch (emailErr) {
            console.error('iPay88 backend: confirmation email failed:', emailErr.message);
          }
        }
      } catch (invoiceErr) {
        console.error('iPay88 backend: invoice/email error (payment already activated):', invoiceErr.message);
      }

    } catch (err) {
      console.error('iPay88 backend: subscription activation error:', err.message);
    }

  } else {
    // Step 4: Failed payment
    try {
      await pool.query(
        `UPDATE payments
            SET status          = 'failed',
                ipay88_response = $1::jsonb
          WHERE id = $2`,
        [ipay88Response, payment.id]
      );
    } catch (err) {
      console.error('iPay88 backend: failed-payment update error:', err.message);
    }
  }

  // Step 5: Always respond '1' — iPay88 retries if it gets anything else
  return respond();
});

// ── Trial reminder email ───────────────────────────────────────────────────────

async function sendTrialReminder(user, daysLeft) {
  if (!process.env.RESEND_API_KEY || !user.email) return;

  const resend = new Resend(process.env.RESEND_API_KEY);
  const billingUrl = `${process.env.APP_URL || 'https://app.measytools.com'}/billing`;

  const subjects = {
    7: `⏰ Your M-EasyTools AI+ trial ends in 7 days`,
    3: `⚠️ 3 days left on your M-EasyTools AI+ trial`,
    1: `🔴 Last day — your M-EasyTools AI+ trial ends tomorrow`,
  };

  const urgency = {
    7: { color: '#E8622A', cta: 'Subscribe Now' },
    3: { color: '#d97706', cta: 'Renew Before It Expires' },
    1: { color: '#ef4444', cta: 'Activate Today — Last Chance' },
  };

  const u = urgency[daysLeft] || urgency[7];
  const name = user.name || 'there';

  const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
</head>
<body style="margin:0;padding:0;background:#f8f9fa;font-family:'Inter',system-ui,sans-serif;">
  <div style="max-width:560px;margin:40px auto;background:#ffffff;border-radius:16px;border:1px solid #e2e8f0;overflow:hidden;">
    <div style="background:${u.color};padding:28px 32px;">
      <div style="display:inline-flex;align-items:center;gap:10px;">
        <div style="width:36px;height:36px;border-radius:10px;background:rgba(255,255,255,0.2);display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;font-size:15px;">M</div>
        <span style="color:#fff;font-size:16px;font-weight:700;letter-spacing:-0.3px;">M-EasyTools AI+</span>
      </div>
    </div>
    <div style="padding:32px;">
      <h2 style="margin:0 0 8px;font-size:22px;font-weight:800;color:#1e293b;letter-spacing:-0.4px;">
        ${daysLeft === 1 ? 'Your trial ends today' : `${daysLeft} days left on your trial`}
      </h2>
      <p style="margin:0 0 24px;color:#475569;font-size:14px;line-height:1.6;">
        Hi ${name}, your free trial of M-EasyTools AI+ ${daysLeft === 1 ? 'expires tomorrow' : `ends in ${daysLeft} days`}.
        Subscribe now to keep full access to your 96 AI content tools, SEO suite, and all your generated documents.
      </p>
      <div style="background:#f8f9fa;border-radius:12px;padding:20px;margin-bottom:24px;border:1px solid #e2e8f0;">
        <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.6px;color:#94a3b8;margin-bottom:12px;">Choose your plan</div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;">
          <div style="flex:1;min-width:160px;background:#fff;border-radius:10px;padding:16px;border:1px solid #e2e8f0;">
            <div style="font-size:22px;font-weight:800;color:#1e293b;">RM365</div>
            <div style="font-size:12px;color:#475569;margin-top:2px;">per year</div>
            <div style="font-size:11px;color:#16a34a;font-weight:600;margin-top:4px;">= RM1/day</div>
          </div>
          <div style="flex:1;min-width:160px;background:#fff;border-radius:10px;padding:16px;border:1px solid #e2e8f0;">
            <div style="font-size:22px;font-weight:800;color:#1e293b;">RM38</div>
            <div style="font-size:12px;color:#475569;margin-top:2px;">per month</div>
            <div style="font-size:11px;color:#94a3b8;font-weight:600;margin-top:4px;">RM456/year</div>
          </div>
        </div>
      </div>
      <a href="${billingUrl}" style="display:block;text-align:center;background:${u.color};color:#ffffff;text-decoration:none;padding:14px 24px;border-radius:10px;font-size:14px;font-weight:700;letter-spacing:-0.2px;">
        ${u.cta} →
      </a>
      <p style="margin:20px 0 0;font-size:12px;color:#94a3b8;text-align:center;line-height:1.6;">
        Your data is safe. Subscribe anytime to restore full access instantly.<br>
        Questions? Reply to this email or visit <a href="https://modusaiassociates.com" style="color:${u.color};">modusaiassociates.com</a>
      </p>
    </div>
    <div style="padding:20px 32px;border-top:1px solid #e2e8f0;background:#f8f9fa;">
      <p style="margin:0;font-size:11px;color:#94a3b8;text-align:center;">
        Modus AI Associates Sdn Bhd · admin@modusaiassociates.com<br>
        You're receiving this because you signed up for a free trial of M-EasyTools AI+.
      </p>
    </div>
  </div>
</body>
</html>`;

  try {
    const fromRaw = process.env.EMAIL_FROM || 'noreply@modusaiassociates.com';
    const from    = fromRaw.includes('<') ? fromRaw : `M-EasyTools AI+ <${fromRaw}>`;
    await resend.emails.send({ from, to: user.email, subject: subjects[daysLeft], html });
    console.log(`Trial reminder (day ${daysLeft}) sent to ${user.email}`);
  } catch (err) {
    console.error(`Failed to send day-${daysLeft} reminder to ${user.email}:`, err.message);
  }
}

module.exports        = router;
module.exports.checkoutHandler   = checkoutHandler;
module.exports.statusHandler     = statusHandler;
module.exports.sendTrialReminder = sendTrialReminder;
