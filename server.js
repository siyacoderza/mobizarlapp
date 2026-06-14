/**
 * ═══════════════════════════════════════════════════════════
 *  Mobizarl — Authentication Server  (v3 — with DB validation)
 *  Korale Systems (Pty) Ltd  ·  K2026201133
 * ═══════════════════════════════════════════════════════════
 *  SMS  →  Africa's Talking  (africastalking.com)
 *  DB   →  Supabase / PostgreSQL  (supabase.com)
 *  Hash →  bcryptjs (cost 12)
 *
 *  Setup:
 *    1.  npm install
 *    2.  cp .env.example .env  →  fill in AT + Supabase credentials
 *    3.  Run schema.sql in your Supabase SQL editor
 *    4.  node seed.js          →  inserts one test user
 *    5.  node server.js
 *    6.  Open http://localhost:3000
 * ═══════════════════════════════════════════════════════════
 */

'use strict';
require('dotenv').config();

const express        = require('express');
const path           = require('path');
const crypto         = require('crypto');
const bcrypt         = require('bcryptjs');
const AT             = require('africastalking');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

/* ─────────────────────────────────────────────────────────
   Supabase client
   Use SERVICE_KEY (not anon key) for server-side queries —
   it bypasses Row Level Security so you can read any row.
───────────────────────────────────────────────────────── */
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

/* ─────────────────────────────────────────────────────────
   Africa's Talking
───────────────────────────────────────────────────────── */
const AT_USERNAME = process.env.AT_USERNAME || 'sandbox';
const at          = AT({ apiKey: process.env.AT_API_KEY, username: AT_USERNAME });
const sms         = at.SMS;
const IS_SANDBOX  = AT_USERNAME === 'sandbox';

/* ─────────────────────────────────────────────────────────
   In-memory stores  (OTPs + sessions)
   OTPs are short-lived (5 min) so memory is fine.
   Sessions: swap for Redis or DB tokens in production.
───────────────────────────────────────────────────────── */
// phone → { otp, expiry, cardNum, userName, initials, muvoTrips, wallet, attempts }
const otpStore = new Map();

// token → { name, initials, phone, cardNum, createdAt }
const sessionStore = new Map();

// phone → { count, windowStart }
const rateStore = new Map();

/* ─────────────────────────────────────────────────────────
   Helpers
───────────────────────────────────────────────────────── */
function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function normPhone(raw) {
  let p = String(raw || '').replace(/[\s\-()]/g, '');
  if (p.startsWith('+'))    p = p.slice(1);
  if (p.startsWith('0027')) p = p.slice(4);
  if (p.startsWith('27'))   p = p.slice(2);
  if (p.startsWith('0'))    p = p.slice(1);
  if (!/^\d{9}$/.test(p))  throw new Error('Invalid SA number');
  return '+27' + p;
}

function maskPhone(e164) {
  return e164.slice(0, 6) + ' *** ' + e164.slice(-4);
}

function getInitials(name) {
  return (name || '??').split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
}

function isRateLimited(phone) {
  const now = Date.now();
  const rec = rateStore.get(phone) || { count: 0, windowStart: now };
  if (now - rec.windowStart > 60 * 60 * 1000) {
    rateStore.set(phone, { count: 1, windowStart: now });
    return false;
  }
  if (rec.count >= 5) return true;
  rec.count++;
  rateStore.set(phone, rec);
  return false;
}

async function sendOtpSms(phone, otp) {
  const result = await sms.send({
    to:      [phone],
    message: `Your Mobizarl code: ${otp}\nValid 5 min. Never share.\n– Korale Systems`,
    ...(IS_SANDBOX ? {} : { from: 'MOBIZARL' }),
  });
  const r = result?.SMSMessageData?.Recipients?.[0];
  console.log(`[AT SMS] ${maskPhone(phone)} → ${r?.status || 'unknown'}  cost: ${r?.cost || 'n/a'}`);
}

/* ─────────────────────────────────────────────────────────
   DB lookup — finds a cardholder by card + phone combo.
   Returns the row or null.  Never throws to the caller.
───────────────────────────────────────────────────────── */
async function findCardholder(card, phone) {
  const { data, error } = await supabase
    .from('cardholders')
    .select('id, full_name, cell_number, password_hash, muvo_trips, wallet_rands, is_active, is_verified')
    .eq('card_number', card)
    .eq('cell_number', phone)
    .single();

  if (error) {
    // PGRST116 = "no rows returned" — not a real error, just no match
    if (error.code !== 'PGRST116') {
      console.error('[DB]', error.message);
    }
    return null;
  }
  return data;
}

/* ─────────────────────────────────────────────────────────
   Routes
───────────────────────────────────────────────────────── */
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'mobizarl.html')));

app.get('/api/health', (_req, res) =>
  res.json({ ok: true, mode: IS_SANDBOX ? 'sandbox' : 'live', ts: Date.now() })
);

/* ══════════════════════════════════════════════════════════
   POST /api/request-otp
   
   Flow:
     1. Validate input formats
     2. Normalise phone to E.164
     3. Look up cardholder by card_number + cell_number  ← NEW
     4. Check is_active flag                             ← NEW
     5. Verify bcrypt password                           ← NEW
     6. Rate-limit check
     7. Generate OTP, store, send via AT
══════════════════════════════════════════════════════════ */
app.post('/api/request-otp', async (req, res) => {
  const { cardNumber, cellNumber, password } = req.body || {};

  /* ── Step 1: Format validation ── */
  const card = String(cardNumber || '').replace(/\D/g, '');
  if (card.length !== 12) {
    return res.status(400).json({ success: false, field: 'card', message: 'Card number must be exactly 12 digits.' });
  }

  let phone;
  try { phone = normPhone(cellNumber); }
  catch {
    return res.status(400).json({ success: false, field: 'cell', message: 'Enter a valid SA mobile number (e.g. 082 345 6789).' });
  }
  if (!/^\+27[678]\d{8}$/.test(phone)) {
    return res.status(400).json({ success: false, field: 'cell', message: 'Number must be a valid SA mobile (06x / 07x / 08x).' });
  }
  if (!password || String(password).length < 6) {
    return res.status(400).json({ success: false, field: 'pass', message: 'Password must be at least 6 characters.' });
  }

  /* ── Step 2: Database lookup ── */
  const user = await findCardholder(card, phone);

  if (!user) {
    // Deliberately vague — don't confirm whether card OR phone is wrong
    console.log(`[Auth] No match — card ...${card.slice(-4)} | ${maskPhone(phone)}`);
    return res.status(401).json({
      success: false,
      message: 'Card number and cellphone do not match our records.',
    });
  }

  /* ── Step 3: Active check ── */
  if (!user.is_active) {
    console.log(`[Auth] Inactive account — card ...${card.slice(-4)}`);
    return res.status(403).json({
      success: false,
      message: 'This card has been deactivated. Please contact your Muvo operator.',
    });
  }

  /* ── Step 4: Password check ── */
  const passwordOk = await bcrypt.compare(String(password), user.password_hash);
  if (!passwordOk) {
    console.log(`[Auth] Wrong password — card ...${card.slice(-4)}`);
    return res.status(401).json({
      success: false,
      field:   'pass',
      message: 'Incorrect password.',
    });
  }

  /* ── Step 5: Rate limit ── */
  if (isRateLimited(phone)) {
    return res.status(429).json({ success: false, message: 'Too many OTP requests. Please wait 60 minutes.' });
  }

  /* ── Step 6: Generate OTP and store with real user data ── */
  const otp = genOtp();
  otpStore.set(phone, {
    otp,
    expiry:    Date.now() + 5 * 60 * 1000,
    cardNum:   card,
    userName:  user.full_name,
    initials:  getInitials(user.full_name),
    muvoTrips: user.muvo_trips,
    wallet:    'R' + Number(user.wallet_rands).toFixed(2),
    attempts:  0,
  });

  console.log(`[OTP] Issued for ${maskPhone(phone)} | ${user.full_name} | card ...${card.slice(-4)}`);
  if (IS_SANDBOX) console.log(`[OTP] Sandbox code: ${otp}`);

  /* ── Step 7: Send SMS ── */
  try {
    await sendOtpSms(phone, otp);
    return res.json({ success: true, maskedPhone: maskPhone(phone) });
  } catch (err) {
    console.error('[AT Error]', err?.message || err);
    otpStore.delete(phone);
    return res.status(500).json({ success: false, message: "Couldn't send OTP. Please try again." });
  }
});

/* ── POST /api/resend-otp ─────────────────────────────── */
app.post('/api/resend-otp', async (req, res) => {
  const { cellNumber } = req.body || {};
  let phone;
  try { phone = normPhone(cellNumber); }
  catch { return res.status(400).json({ success: false, message: 'Invalid number. Please go back and re-enter.' }); }

  const existing = otpStore.get(phone);
  if (!existing) {
    return res.status(400).json({ success: false, message: 'Session expired. Please go back and log in again.' });
  }
  if (isRateLimited(phone)) {
    return res.status(429).json({ success: false, message: 'Too many requests. Please wait a few minutes.' });
  }

  const otp = genOtp();
  otpStore.set(phone, { ...existing, otp, expiry: Date.now() + 5 * 60 * 1000, attempts: 0 });

  if (IS_SANDBOX) console.log(`[OTP Resend] Sandbox code: ${otp}`);

  try {
    await sendOtpSms(phone, otp);
    return res.json({ success: true, maskedPhone: maskPhone(phone) });
  } catch (err) {
    otpStore.delete(phone);
    return res.status(500).json({ success: false, message: "Couldn't resend OTP. Please try again." });
  }
});

/* ── POST /api/verify-otp ─────────────────────────────── */
app.post('/api/verify-otp', async (req, res) => {
  const { cellNumber, otp } = req.body || {};
  let phone;
  try { phone = normPhone(cellNumber); }
  catch { return res.status(400).json({ success: false, message: 'Invalid number.' }); }

  const record = otpStore.get(phone);
  if (!record)               return res.status(400).json({ success: false, message: 'No active OTP. Please request a new one.' });
  if (Date.now() > record.expiry) { otpStore.delete(phone); return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' }); }
  if (record.attempts >= 3)  { otpStore.delete(phone); return res.status(429).json({ success: false, message: 'Too many incorrect attempts. Please request a new OTP.' }); }

  const submitted = String(otp || '').replace(/\D/g, '');
  if (submitted !== record.otp) {
    record.attempts++;
    const left = 3 - record.attempts;
    return res.status(400).json({ success: false, message: `Incorrect OTP. ${left} attempt${left !== 1 ? 's' : ''} remaining.` });
  }

  /* ✓ OTP correct — create session with real user data from otpStore */
  otpStore.delete(phone);
  const token = crypto.randomBytes(32).toString('hex');

  sessionStore.set(token, {
    phone,
    cardNum:   record.cardNum,
    name:      record.userName,
    initials:  record.initials,
    muvoTrips: record.muvoTrips,
    wallet:    record.wallet,
    createdAt: Date.now(),
  });

  /* Update last_login in DB (fire and forget) */
  supabase
    .from('cardholders')
    .update({ last_login: new Date().toISOString() })
    .eq('card_number', record.cardNum)
    .then(({ error }) => { if (error) console.warn('[DB] last_login update failed:', error.message); });

  console.log(`[Session] Created for ${maskPhone(phone)} | ${record.userName} | token ...${token.slice(-8)}`);

  return res.json({
    success: true,
    token,
    user: {
      name:      record.userName,
      initials:  record.initials,
      cardLast4: record.cardNum.slice(-4),
      muvoTrips: record.muvoTrips,
      wallet:    record.wallet,
    },
  });
});

/* ── POST /api/logout ─────────────────────────────────── */
app.post('/api/logout', (req, res) => {
  const { token } = req.body || {};
  if (token && sessionStore.has(token)) {
    console.log(`[Session] Revoked ...${token.slice(-8)}`);
    sessionStore.delete(token);
  }
  res.json({ success: true });
});

/* ─────────────────────────────────────────────────────────
   Cleanup every 10 min
───────────────────────────────────────────────────────── */
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otpStore)     if (now > v.expiry)                    otpStore.delete(k);
  for (const [k, v] of sessionStore) if (now - v.createdAt > 24*60*60*1000) sessionStore.delete(k);
  for (const [k, v] of rateStore)    if (now - v.windowStart > 60*60*1000)  rateStore.delete(k);
}, 10 * 60 * 1000);

/* ─────────────────────────────────────────────────────────
   Start
───────────────────────────────────────────────────────── */
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => {
  console.log('\n  ╔══════════════════════════════════════════╗');
  console.log('  ║     🚌  Mobizarl  |  Korale Systems     ║');
  console.log('  ╚══════════════════════════════════════════╝');
  console.log(`  URL  →  http://localhost:${PORT}`);
  console.log(`  DB   →  Supabase (${process.env.SUPABASE_URL ? '✓ connected' : '✗ SUPABASE_URL missing'})`);
  console.log(`  SMS  →  Africa's Talking (${IS_SANDBOX ? 'SANDBOX' : '🟢 LIVE'})`);
  if (IS_SANDBOX) console.log(`  SIM  →  https://simulator.africastalking.com\n`);
  else            console.log('');
});
