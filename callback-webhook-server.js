/**
 * CallBack AI — Missed Call Recovery Webhook Server (HARDENED)
 * ─────────────────────────────────────────────────────────────
 * Stack: Node.js + Express + Twilio + Claude API + Supabase
 *
 * SETUP:
 *   npm install express twilio @anthropic-ai/sdk @supabase/supabase-js dotenv helmet express-rate-limit
 *
 * ENV VARS (.env file):
 *   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 *   TWILIO_AUTH_TOKEN=your_auth_token
 *   TWILIO_PHONE_NUMBER=+353xxxxxxxxx
 *   ANTHROPIC_API_KEY=sk-ant-xxxxxxxxx
 *   SUPABASE_URL=https://xxxx.supabase.co
 *   SUPABASE_SERVICE_KEY=your_service_role_key
 *   API_SECRET=your_long_random_secret_for_dashboard_api
 *   PORT=3000
 *
 * GENERATE API_SECRET:
 *   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */

// ─── Global error handlers — must be first ───────────────────────────────────
// Log every crash with a full stack trace so Railway logs show the root cause.
//
// IMPORTANT: uncaughtException must NOT call process.exit().
// If it does, any background async error (JWKS fetch, Clerk init, etc.) that
// throws after the startup banner will kill the server, Railway restarts it,
// same error fires, infinite crash loop. Log and keep running instead.
process.on('uncaughtException',  (err) => console.error('UNCAUGHT EXCEPTION:', err.stack || err));
process.on('unhandledRejection', (err) => console.error('UNHANDLED REJECTION:', err));

// Graceful shutdown on SIGTERM (Railway sends this before every new deployment).
// server.close() stops new connections but won't fire its callback until ALL
// existing connections (including Railway's persistent health-check connection)
// close naturally. Without a timeout this hangs forever → Railway sends SIGKILL
// → new deployment starts → same thing → crash loop.
process.on('SIGTERM', () => {
  console.log('[shutdown] SIGTERM received — closing server gracefully');
  // Force-exit after 5 s if server.close() hasn't drained all connections.
  const forceExit = setTimeout(() => {
    console.warn('[shutdown] server.close() did not finish in 5 s — forcing exit');
    process.exit(0);
  }, 5_000);
  // Don't let this timer keep the event loop alive on its own.
  if (forceExit.unref) forceExit.unref();

  if (typeof server !== 'undefined') {
    server.close(() => {
      console.log('[shutdown] HTTP server closed cleanly');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

require('dotenv').config();

// ─── Validate env vars BEFORE any client initialisation ──────────────────────
// Stripe(undefined) throws an uncaught exception — if this check runs after
// the Stripe() call and STRIPE_SECRET_KEY is missing, the process crashes with
// no useful log. Check first, crash with a clear message if anything is absent.
const REQUIRED_ENV = [
  'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER',
  'ANTHROPIC_API_KEY', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY',
  'STRIPE_SECRET_KEY', 'STRIPE_PRICE_ID', 'STRIPE_WEBHOOK_SECRET', 'CLERK_SECRET_KEY',
];
const OPTIONAL_ENV = [
  'RAILWAY_URL',   // fallback to hardcoded Railway domain if absent
  'RESEND_API_KEY', // welcome email — skipped silently if absent
  'PORT',           // defaults to 3000
];

// Log every var by name (NOT value) so Railway logs show exactly what is/isn't set
REQUIRED_ENV.forEach(k => console.log(`[startup] ${k}: ${process.env[k] ? 'SET' : 'MISSING ⚠️'}`));
OPTIONAL_ENV.forEach(k => console.log(`[startup] ${k}: ${process.env[k] ? 'SET' : 'not set (optional)'}`));

const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length > 0) {
  console.error(`STARTUP FAILED — missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

const express   = require('express');
const path      = require('path');
const twilio    = require('twilio');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const cors      = require('cors');
const Stripe    = require('stripe');
// Safe to call now — STRIPE_SECRET_KEY is guaranteed to exist
const stripe    = Stripe(process.env.STRIPE_SECRET_KEY);
let verifyToken = null;
try {
  ({ verifyToken } = require('@clerk/backend'));
  console.log('[startup] @clerk/backend loaded');
} catch (err) {
  console.error('[startup] @clerk/backend FAILED to load:', err.message);
  // verifyToken remains null — requireAuth will reject all requests with a 503
}

// ─── App setup ────────────────────────────────────────────────────────────────

const app = express();
app.set('trust proxy', 1);

// Security headers — blocks XSS, clickjacking, MIME sniffing, etc.
app.use(helmet());
app.disable('x-powered-by');

app.use(cors({
  origin: [
    'https://callbackai.ie',
    'https://www.callbackai.ie',
    'https://callbackai-production.up.railway.app',
    'http://localhost:3000',
  ],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Email'],
}));

// ─── Static file serving ──────────────────────────────────────────────────────
// Serve the frontend HTML/CSS/JS files from the project root.
// Must come BEFORE rate-limiters and body parsers so asset requests
// (fonts, scripts, etc.) are handled immediately without hitting API middleware.
app.use(express.static(__dirname, {
  // Don't serve the server file itself or .env
  dotfiles: 'deny',
}));

// Explicit root → landing page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Rate limiting — prevents SMS bombing and brute force
const webhookLimiter  = rateLimit({ windowMs: 60_000,      max: 60 });
const apiLimiter      = rateLimit({ windowMs: 60_000,      max: 30 });
const onboardLimiter  = rateLimit({ windowMs: 60 * 60_000, max: 5  }); // 5 signups/hr/IP
app.use('/webhook',       webhookLimiter);
app.use('/api',           apiLimiter);
app.use('/api/onboard',   onboardLimiter);

// ─── Provisioning helper ──────────────────────────────────────────────────────
// Called by the Stripe webhook after checkout.session.completed.
// Buys a Twilio number, creates the Supabase record, sends the welcome email.

async function provisionBusiness({ businessName, industry, phone, email, clerkUserId, stripeCustomerId, stripeSubscriptionId }) {
  const bizName    = safeName(businessName);
  const cleanPhone = String(phone).replace(/\s/g, '');

  console.log(`[provision] START | biz: "${bizName}" | email: ${maskEmail(email)} | phone: ${maskPhone(cleanPhone)}`);
  console.log(`[provision] stripeCustomerId: ${stripeCustomerId || 'none'} | stripeSubscriptionId: ${stripeSubscriptionId || 'none'}`);
  console.log('[provision] checking for existing business with email:', maskEmail(email));

  // ── Idempotency check ──────────────────────────────────────────────────────
  // Only skip if the business exists AND already has a stripe_subscription_id.
  // A row without a subscription means a previous provision failed mid-way —
  // allow re-provisioning so the customer isn't left without a number.
  const { data: existing, error: existingError } = await supabase
    .from('businesses')
    .select('id, twilio_number, stripe_subscription_id')
    .eq('email', email)
    .maybeSingle();

  if (existingError) {
    console.error(`[provision] idempotency check FAILED — Supabase error: ${existingError.message}`, existingError);
    throw new Error(`Idempotency check failed: ${existingError.message}`);
  }

  console.log(`[provision] idempotency check result: existing=${existing ? existing.id : 'none'} | stripe_subscription_id=${existing?.stripe_subscription_id || 'none'}`);

  if (existing && existing.stripe_subscription_id) {
    console.log(`[provision] idempotent — already provisioned: ${existing.id}`);
    return existing;
  }

  if (existing && !existing.stripe_subscription_id) {
    console.log(`[provision] found existing row without subscription — re-provisioning (id: ${existing.id})`);
  } else {
    console.log(`[provision] no existing record found — proceeding with provisioning`);
  }

  // ── Step 1: Search for available US number ────────────────────────────────
  console.log('[provision] STEP 1 — searching for available US Twilio number...');
  const available = await twilioClient.availablePhoneNumbers('US')
    .local.list({ smsEnabled: true, voiceEnabled: true, limit: 1 });

  if (!available.length) throw new Error('No US numbers available');

  const availableNumber = available[0].phoneNumber;
  console.log(`[provision] STEP 1 OK — found number ${maskPhone(availableNumber)}`);

  // ── Step 2: Purchase the number ───────────────────────────────────────────
  console.log('[provision] STEP 2 — purchasing Twilio number...');
  const purchased = await twilioClient.incomingPhoneNumbers.create({
    phoneNumber:          availableNumber,
    voiceUrl:             `${RAILWAY_URL}/webhook/incoming-call`,
    voiceMethod:          'POST',
    statusCallback:       `${RAILWAY_URL}/webhook/call-status`,
    statusCallbackMethod: 'POST',
    smsUrl:               `${RAILWAY_URL}/webhook/sms-reply`,
    smsMethod:            'POST',
  });

  const twilioNumber = purchased.phoneNumber;
  console.log(`[provision] STEP 2 OK — purchased ${maskPhone(twilioNumber)}`);

  // ── Step 3: Create the Supabase record ────────────────────────────────────
  console.log(`[provision] STEP 3 — attempting Supabase INSERT for email: ${maskEmail(email)}`);
  const insertPayload = {
    name:                   bizName,
    email:                  email,
    industry:               isValidIndustry(industry) ? industry : 'general',
    phone:                  cleanPhone,
    twilio_number:          twilioNumber,
    status:                 'active',
    setup_completed:        false,
    stripe_customer_id:     stripeCustomerId || null,
    stripe_subscription_id: stripeSubscriptionId || null,
  };
  console.log(`[provision] STEP 3 — insert payload (no PII):`, {
    name:                   insertPayload.name,
    industry:               insertPayload.industry,
    status:                 insertPayload.status,
    setup_completed:        insertPayload.setup_completed,
    twilio_number:          maskPhone(insertPayload.twilio_number),
    stripe_customer_id:     insertPayload.stripe_customer_id ? 'SET' : 'null',
    stripe_subscription_id: insertPayload.stripe_subscription_id ? 'SET' : 'null',
  });

  const { data: newBusiness, error: dbError } = await supabase
    .from('businesses')
    .insert(insertPayload)
    .select('id')
    .single();

  if (dbError) {
    console.error(`[provision] STEP 3 FAILED — Supabase insert error:`, dbError);
    console.error(`[provision] STEP 3 error detail: code=${dbError.code} | hint=${dbError.hint} | details=${dbError.details}`);
    throw new Error(`Supabase insert failed: ${dbError.message}`);
  }

  console.log(`[provision] STEP 3 OK — record created | id: ${newBusiness.id}`);

  // ── Step 4: Welcome email (fire-and-forget) ────────────────────────────────
  console.log(`[provision] STEP 4 — sending welcome email...`);
  sendWelcomeEmail(email, bizName, twilioNumber).catch(err =>
    console.error('[provision] STEP 4 FAILED — welcome email error:', err.message)
  );

  console.log(`[provision] COMPLETE — "${bizName}" | id: ${newBusiness.id} | number: ${maskPhone(twilioNumber)} | email: ${maskEmail(email)}`);
}

// ─── ROUTE: Stripe webhook ────────────────────────────────────────────────────
// MUST be declared before express.json() — Stripe signature verification
// requires the raw request buffer, not the parsed JSON object.

app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.warn('[stripe-webhook] signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log(`[stripe-webhook] event: ${event.type}`);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    // Log the full metadata so we can verify what Stripe actually sent
    console.log('[stripe-webhook] session.id:', session.id);
    console.log('[stripe-webhook] session.metadata:', JSON.stringify(session.metadata || {}));
    console.log('[stripe-webhook] session.customer:', session.customer);
    console.log('[stripe-webhook] session.subscription:', session.subscription);

    const { businessName, industry, phone, email, clerkUserId } = session.metadata || {};

    if (!email || !businessName || !phone) {
      console.error('[stripe-webhook] MISSING METADATA — email:', !!email, '| businessName:', !!businessName, '| phone:', !!phone, '| session:', session.id);
      return res.json({ received: true });
    }

    console.log(`[stripe-webhook] metadata OK — passing to provisionBusiness | email: ${maskEmail(email)} | biz: "${businessName}"`);

    // Acknowledge immediately — provisioning runs asynchronously
    res.json({ received: true });

    provisionBusiness({
      businessName,
      industry,
      phone,
      email,
      clerkUserId:          clerkUserId || null,
      stripeCustomerId:     session.customer,
      stripeSubscriptionId: session.subscription,
    }).catch(err => {
      console.error('[stripe-webhook] provisionBusiness threw:', err.message);
      console.error('[stripe-webhook] provisionBusiness stack:', err.stack);
    });

  } else {
    res.json({ received: true });
  }
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '10kb' }));

// ─── Clients ─────────────────────────────────────────────────────────────────

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

let anthropic = null;
try {
  anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  console.log('[startup] Anthropic client initialised');
} catch (err) {
  console.error('[startup] Anthropic client FAILED to initialise:', err.message);
  // anthropic remains null — routes that use it will fall back to static SMS
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const RAILWAY_URL = process.env.RAILWAY_URL || 'https://callbackai-production.up.railway.app';
console.log('[startup] RAILWAY_URL:', RAILWAY_URL);

// ─── Industry tone map ────────────────────────────────────────────────────────

const INDUSTRY_TONES = {
  trades:     'You are a friendly, reliable local tradesperson. Tone: warm, practical. End with a clear next step.',
  dental:     'You are a professional dental clinic receptionist. Tone: reassuring, appointment-focused.',
  salon:      'You are a friendly hair or beauty salon. Tone: warm, welcoming, booking-focused.',
  realestate: 'You are a responsive property agent. Tone: professional, prompt, value-focused.',
  restaurant: 'You are a welcoming restaurant. Tone: warm, friendly, reservation-focused.',
  general:    'You are a friendly local business. Tone: professional and warm.',
};

// ─── Twilio signature validation middleware ───────────────────────────────────
// Verifies every webhook is genuinely from Twilio, not a spoofed attacker.
// Without this anyone can hit your endpoint and trigger fake SMS sends.

function validateTwilioSignature(req, res, next) {
  const twilioSignature = req.headers['x-twilio-signature'];

  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const host     = req.headers['x-forwarded-host']  || req.get('host');
  const url      = `${protocol}://${host}${req.originalUrl}`;

  const isValid = twilio.validateRequest(
    process.env.TWILIO_AUTH_TOKEN,
    twilioSignature,
    url,
    req.body
  );

  if (!isValid) {
    console.warn(`Invalid Twilio signature from ${req.ip} on ${req.path}`);
    return res.status(403).send('Forbidden');
  }
  next();
}

// ─── Clerk JWT auth middleware ────────────────────────────────────────────────
// Verifies Clerk session tokens on dashboard API routes.

async function requireAuth(req, res, next) {
  if (!verifyToken) {
    console.error('[requireAuth] @clerk/backend not loaded — rejecting request');
    return res.status(503).json({ error: 'Auth service unavailable' });
  }
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

  console.log(`[requireAuth] ${req.method} ${req.path} | token: ${token ? token.slice(0, 20) + '...' : 'MISSING'} | email: ${req.headers['x-user-email'] || 'none'} | origin: ${req.headers['origin'] || 'none'}`);

  if (!token) return res.status(401).json({ error: 'Unauthorised' });

  try {
    // Race against a 5-second timeout — verifyToken fetches JWKS on first call
    // and can hang indefinitely if the Clerk CDN is slow or unreachable.
    await Promise.race([
      verifyToken(token, { secretKey: process.env.CLERK_SECRET_KEY }),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error('verifyToken timed out after 5s')), 5000)
      ),
    ]);
    console.log(`[requireAuth] OK — ${req.method} ${req.path}`);
    next();
  } catch (err) {
    console.warn(`[requireAuth] FAILED — ${req.method} ${req.path} | error: ${err.message}`);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── [FIX 6] Input validation ────────────────────────────────────────────────
// Validate and sanitise all external input before use.

const E164_REGEX = /^\+[1-9]\d{7,14}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const EMAIL_REGEX = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const PM_REGEX    = /^pm_[A-Za-z0-9]{6,}/;

const isValidPhone    = n  => typeof n === 'string' && E164_REGEX.test(n.trim());
const isValidUUID     = id => typeof id === 'string' && UUID_REGEX.test(id);
const isValidIndustry = i  => Object.keys(INDUSTRY_TONES).includes(i);
const isValidEmail    = e  => typeof e === 'string' && e.length <= 254 && EMAIL_REGEX.test(e);
const isValidPmId     = id => typeof id === 'string' && PM_REGEX.test(id);
const safeName        = s  => String(s || '').slice(0, 100).replace(/[<>"']/g, '');

// Privacy-safe log helpers — used during provisioning so no PII hits Railway logs
const maskPhone = n => (typeof n === 'string' && n.length > 8) ? n.slice(0, 4) + '***' + n.slice(-4) : '***';
const maskEmail = e => { if (!e?.includes('@')) return '***'; const [l, d] = e.split('@'); return l[0] + '***@' + d; };

// Send a welcome email via Resend (https://resend.com).
// If RESEND_API_KEY is not set we warn and skip — never block onboarding.
async function sendWelcomeEmail(toEmail, bizName, twilioNumber) {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    console.warn('[email] RESEND_API_KEY not set — skipping welcome email');
    return;
  }

  const displayNumber = twilioNumber || 'your CallBack AI number';
  const dialCode      = twilioNumber ? `**61*${twilioNumber}#` : '**61*[your number]#';
  const name          = safeName(bizName);

  const textBody = `Hi ${name},

Thanks for joining CallBack AI. Here's everything you need to get started.

Your dedicated number is:
${displayNumber}

To activate it, dial this from your phone and press call:
${dialCode}

That's it. Takes about 10 seconds. Once that's done, any call you miss will get an automatic text back within 14 seconds.

If the dial code doesn't work, here are the instructions for your network:

Vodafone: Call 1907 and ask them to set up unanswered call divert to ${displayNumber}
Three: My3 app → Account → Call settings → Call divert → No answer → enter ${displayNumber}
Eir: Call 1901 and ask them to set up unanswered call divert to ${displayNumber}
Landline: Dial ${dialCode} from your phone and press call

Your dashboard is at callbackai.ie/callback-dashboard.html — that's where you'll see all your missed calls and conversations.

If you have any questions just reply to this email and I'll get back to you.

Ryan
CallBack AI`.trim();

  const p  = 'margin:0 0 20px;font-family:Arial,Georgia,sans-serif;font-size:15px;line-height:1.65;color:#333333';
  const sm = 'margin:0 0 6px;font-family:Arial,Georgia,sans-serif;font-size:13px;line-height:1.5;color:#666666';

  const htmlBody = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f9f9f9">
<div style="max-width:600px;margin:0 auto;padding:32px 16px">
<div style="background:#ffffff;padding:32px 24px;border-radius:4px">

  <p style="${p}">Hi ${name},</p>

  <p style="${p}">Thanks for joining CallBack AI. Here's everything you need to get started.</p>

  <p style="${sm}">Your dedicated number:</p>
  <p style="margin:0 0 20px;font-family:'Courier New',monospace;font-size:18px;font-weight:700;color:#333333">${displayNumber}</p>

  <p style="${sm}">To activate it, dial this from your phone and press call:</p>
  <p style="margin:0 0 20px;font-family:'Courier New',monospace;font-size:18px;font-weight:700;color:#333333">${dialCode}</p>

  <p style="${p}">That's it. Takes about 10 seconds. Once that's done, any call you miss will get an automatic text back within 14 seconds.</p>

  <p style="margin:0 0 8px;font-family:Arial,Georgia,sans-serif;font-size:15px;line-height:1.65;color:#333333">If the dial code doesn't work, here are the instructions for your network:</p>
  <table style="width:100%;border-collapse:collapse;margin:0 0 20px;font-family:Arial,Georgia,sans-serif;font-size:14px;color:#333333">
    <tr style="border-bottom:1px solid #eeeeee">
      <td style="padding:9px 12px 9px 0;font-weight:600;white-space:nowrap;vertical-align:top;width:90px">Vodafone</td>
      <td style="padding:9px 0;color:#555555">Call <strong>1907</strong> and ask them to set up unanswered call divert to ${displayNumber}</td>
    </tr>
    <tr style="border-bottom:1px solid #eeeeee">
      <td style="padding:9px 12px 9px 0;font-weight:600;white-space:nowrap;vertical-align:top">Three</td>
      <td style="padding:9px 0;color:#555555">My3 app → Account → Call settings → Call divert → No answer → enter ${displayNumber}</td>
    </tr>
    <tr style="border-bottom:1px solid #eeeeee">
      <td style="padding:9px 12px 9px 0;font-weight:600;white-space:nowrap;vertical-align:top">Eir</td>
      <td style="padding:9px 0;color:#555555">Call <strong>1901</strong> and ask them to set up unanswered call divert to ${displayNumber}</td>
    </tr>
    <tr>
      <td style="padding:9px 12px 9px 0;font-weight:600;white-space:nowrap;vertical-align:top">Landline</td>
      <td style="padding:9px 0;color:#555555">Dial <strong>${dialCode}</strong> from your phone and press call</td>
    </tr>
  </table>

  <p style="${p}">Your dashboard is at <a href="https://callbackai.ie/callback-dashboard.html" style="color:#333333">callbackai.ie/callback-dashboard.html</a> — that's where you'll see all your missed calls and conversations.</p>

  <p style="${p}">If you have any questions just reply to this email and I'll get back to you.</p>

  <p style="margin:0;font-family:Arial,Georgia,sans-serif;font-size:15px;line-height:1.65;color:#333333">Ryan<br>CallBack AI</p>

</div>
</div>
</body>
</html>`;

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from:     'Ryan at CallBack AI <welcome@callbackai.ie>',
        reply_to: 'welcome@callbackai.ie',
        to:       [toEmail],
        subject:  'Thanks for joining CallBack AI',
        html:     htmlBody,
        text:     textBody,
      }),
    });
    if (!r.ok) {
      const body = await r.text();
      console.error(`[email] Resend error ${r.status}:`, body.slice(0, 200));
    } else {
      console.log(`[email] welcome email sent to ${maskEmail(toEmail)}`);
    }
  } catch (err) {
    console.error('[email] fetch failed:', err.message);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function getBusinessByTwilioNumber(twilioNumber) {
  const { data, error } = await supabase
    .from('businesses')
    .select('id, name, industry, custom_sms_template') // never select * — least privilege
    .eq('twilio_number', twilioNumber)
    .single();
  if (error || !data) return null;
  return data;
}

async function generateSMS(business) {
  const industry = isValidIndustry(business.industry) ? business.industry : 'general';
  const name     = safeName(business.name);

  if (business.custom_sms_template) {
    return business.custom_sms_template.slice(0, 160).replace('{{business_name}}', name);
  }

  // Industry-specific opening SMS — static templates, no AI needed.
  // Each is under 160 chars and ends with a clear call-to-action.
  const INITIAL_SMS = {
    trades:     `Hi, sorry we missed your call at ${name}! Are you looking for a quote or is it an urgent job? Reply here and we'll get back to you fast.`,
    dental:     `Hi, sorry we missed your call at ${name}! Would you like to book an appointment? Reply here and we'll sort it out.`,
    salon:      `Hi, sorry we missed your call at ${name}! Looking to book a treatment or check availability? Reply here!`,
    realestate: `Hi, sorry we missed your call at ${name}! Are you looking to buy, sell or rent? Reply here and we'll be right with you.`,
    restaurant: `Hi, sorry we missed your call at ${name}! Looking to make a reservation? Reply here and we'll get you sorted.`,
    general:    `Hi, sorry we missed your call at ${name}! How can we help? Reply here and we'll get back to you shortly.`,
  };

  return INITIAL_SMS[industry].slice(0, 160);
}


async function logMessage(callId, direction, body) {
  const { error } = await supabase.from('messages').insert({ call_id: callId, direction, body });
  if (error) console.error('logMessage error:', error.message);
}

async function updateCallStatus(callId, status) {
  const { error } = await supabase.from('calls').update({ status }).eq('id', callId);
  if (error) console.error('updateCallStatus error:', error.message);
}

// ─── AI SMS conversation helpers ──────────────────────────────────────────────

// In-memory rate limiter: tracks the last AI reply timestamp per caller number.
// Prevents AI reply loops and SMS bombing — max 1 AI reply per minute per number.
// Map<E164Phone, lastRepliedMs>
const _aiRateLimit = new Map();
const AI_RATE_LIMIT_MS = 60_000; // 1 minute

// After this many messages in a thread we stop the AI and send a human handoff.
// Prevents infinite loops and keeps Railway costs bounded.
const AI_MAX_MESSAGES = 10;

// Sent when Claude API fails or a prompt injection attempt is detected.
const SMS_FALLBACK = "Thanks for your message — we'll be in touch shortly!";

// Sent when the conversation hits the message limit.
const SMS_HANDOFF  = "Thanks so much for the details! I've passed everything on and someone from the team will be in touch very shortly to sort everything out. Talk soon!";

// Prompt-injection guard patterns.
// If any match the inbound SMS we skip Claude entirely and send the fallback.
// This prevents callers from hijacking the AI's behaviour via crafted messages.
const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /forget\s+(everything|all|previous|prior)/i,
  /you\s+are\s+now\s+(a|an)\s/i,
  /new\s+(system\s+)?prompt/i,
  /override\s+(your\s+)?(instructions|rules|guidelines)/i,
  /jailbreak/i,
  /\bDAN\b/,  // "Do Anything Now" jailbreak variant
];

/**
 * Sanitise an inbound SMS before passing to Claude.
 * - Truncates at 500 chars to cap prompt size.
 * - Returns null if an injection pattern is matched (triggers fallback).
 * The raw body (up to 1600 chars) is still stored in the DB; only
 * the sanitised version is ever sent to the Claude API.
 */
function sanitiseSmsBody(raw) {
  const text = String(raw || '').trim().slice(0, 500);
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) return null;
  }
  return text;
}

/**
 * Build the Claude system prompt for a given business.
 * Receives ONLY name and industry — never email, Stripe IDs, or phone number.
 * The customer's phone number is also never included anywhere in the prompt.
 */
function buildAiSystemPrompt(bizName, bizIndustry) {
  const industry = isValidIndustry(bizIndustry) ? bizIndustry : 'general';
  const name     = safeName(bizName);

  const industryDesc = {
    trades:     'a local trades business (e.g. plumbing, electrical, or carpentry)',
    dental:     'a dental clinic',
    salon:      'a hair and beauty salon',
    realestate: 'a property agency',
    restaurant: 'a restaurant',
    general:    'a local business',
  }[industry];

  const industryContext = {
    trades:     'Help the customer describe the job (type of work, location, urgency). Do not quote prices — say the owner will assess and call back to confirm.',
    dental:     'Help the customer book or enquire about an appointment (checkup, treatment, emergency). Do not state availability — say the team will confirm times.',
    salon:      'Help the customer book a treatment or check availability (haircut, colour, nails, etc.). Do not confirm slots — say the team will check the diary.',
    realestate: 'Find out if they are buying, selling or renting, and any key details (area, budget range, property type). Do not make promises about listings or valuations.',
    restaurant: 'Help with a reservation — ask for date, time, party size and any dietary needs. Do not confirm availability — say the team will confirm the booking.',
    general:    'Find out what the customer needs and gather enough detail so the owner can call back and help them properly.',
  }[industry];

  return `You are a helpful assistant for ${name}, ${industryDesc} in Ireland.
A customer missed a call from ${name} and you are following up via SMS on their behalf.
${industryContext}
Be warm, friendly and professional.
Keep every reply short and conversational — under 160 characters where possible.
Never make up specific prices, times or availability — always say the owner will confirm details.
Never claim to be human if asked directly — say you are an AI assistant for ${name}.
If the customer wants to book or needs urgent help, say the owner will call them back shortly.`;
}

/**
 * Send an SMS via the Twilio API and log it to the messages table.
 * IMPORTANT: We log only the message ID to Railway logs — never the content.
 */
async function sendAndLogSms(fromNumber, toNumber, body, callId) {
  try {
    const result = await twilioClient.messages.create({ body, from: fromNumber, to: toNumber });
    // Log SID only — content is never written to logs (privacy)
    console.log(`[ai-sms] sent | call: ${callId} | twilio_sid: ${result.sid}`);
  } catch (err) {
    console.error(`[ai-sms] Twilio send failed | call: ${callId} | ${err.message}`);
    return; // Don't log a message that was never delivered
  }
  const { data: msg, error } = await supabase
    .from('messages')
    .insert({ call_id: callId, direction: 'outbound', body })
    .select('id').single();
  if (!error) console.log(`[ai-sms] logged outbound | msg_id: ${msg.id} | call: ${callId}`);
}

/**
 * Core AI reply logic — called asynchronously after the Twilio webhook
 * has already received its <Response/> so we're not racing the 15s timeout.
 *
 * Security measures applied here:
 *  - Rate limit: max 1 AI reply / 60s per caller number
 *  - Injection guard: sanitiseSmsBody() rejects crafted messages
 *  - Message limit: AI stops at AI_MAX_MESSAGES and hands off to human
 *  - Minimal data to Claude: only business name + industry, no PII
 *  - Claude API failure: always falls back to SMS_FALLBACK, never throws
 */
async function processInboundSms(from, rawBody, toNumber) {
  // ── 1. Retrieve the most recent call for this caller ─────────────────────
  const { data: calls } = await supabase
    .from('calls')
    .select('id, business_id')
    .eq('caller_number', from)
    .order('created_at', { ascending: false })
    .limit(1);

  if (!calls?.length) {
    console.log('[ai-sms] no call record found, skipping');
    return;
  }

  const { id: callId, business_id: businessId } = calls[0];

  // ── 2. Log the inbound message (ID only to logs, full body to DB) ─────────
  const safeBody = String(rawBody || '').slice(0, 1600);
  const { data: inMsg } = await supabase
    .from('messages')
    .insert({ call_id: callId, direction: 'inbound', body: safeBody })
    .select('id').single();
  console.log(`[ai-sms] logged inbound | msg_id: ${inMsg?.id} | call: ${callId}`);

  await updateCallStatus(callId, 'replied');

  // ── 3. Rate limit — max 1 AI reply per minute per caller number ───────────
  const now       = Date.now();
  const lastReply = _aiRateLimit.get(from);
  if (lastReply && (now - lastReply) < AI_RATE_LIMIT_MS) {
    console.log(`[ai-sms] rate limited | call: ${callId}`);
    return;
  }

  // ── 4. Injection guard — check before anything reaches Claude ─────────────
  const cleanBody = sanitiseSmsBody(safeBody);
  if (cleanBody === null) {
    // Injection pattern detected — send safe fallback, log nothing about content
    console.log(`[ai-sms] injection pattern detected | call: ${callId} | sending fallback`);
    _aiRateLimit.set(from, now);
    await sendAndLogSms(toNumber, from, SMS_FALLBACK, callId);
    return;
  }

  // ── 5. Fetch conversation history (after logging inbound so it's included) ─
  const { data: messages } = await supabase
    .from('messages')
    .select('id, direction, body, sent_at')
    .eq('call_id', callId)
    .order('sent_at', { ascending: true });

  if (!messages?.length) return;

  // ── 6. Message limit — hand off to human after AI_MAX_MESSAGES ────────────
  if (messages.length >= AI_MAX_MESSAGES) {
    console.log(`[ai-sms] message limit reached (${messages.length}) | call: ${callId}`);
    _aiRateLimit.set(from, now);
    await sendAndLogSms(toNumber, from, SMS_HANDOFF, callId);
    return;
  }

  // ── 7. Fetch business — name and industry only, no PII ────────────────────
  const { data: business } = await supabase
    .from('businesses')
    .select('name, industry') // deliberately omits email, stripe IDs, phone
    .eq('id', businessId)
    .single();

  if (!business) {
    console.log(`[ai-sms] business not found for id: ${businessId}`);
    return;
  }

  // ── 8. Build Claude messages array from conversation history ─────────────
  // The very first message is usually the outbound "missed call" auto-text.
  // Claude requires the first turn to be 'user', so we skip leading outbound
  // messages and include the first one as context in the system prompt.
  let firstOutboundBody = null;
  let historyToConvert  = messages;

  if (messages[0]?.direction === 'outbound') {
    firstOutboundBody = messages[0].body;
    historyToConvert  = messages.slice(1);
  }

  // Map inbound → user, outbound → assistant.
  // Merge consecutive same-role messages so Claude never gets adjacent same-role turns.
  // Customer phone number is NEVER included in any message content sent to Claude.
  const claudeMessages = [];
  for (const msg of historyToConvert) {
    const role = msg.direction === 'inbound' ? 'user' : 'assistant';
    if (claudeMessages.length > 0 && claudeMessages[claudeMessages.length - 1].role === role) {
      claudeMessages[claudeMessages.length - 1].content += '\n' + msg.body;
    } else {
      claudeMessages.push({ role, content: msg.body });
    }
  }

  // Bail out if there's nothing for Claude to respond to
  if (!claudeMessages.length || claudeMessages[0].role !== 'user') {
    console.log(`[ai-sms] no user turn yet | call: ${callId} | skipping`);
    return;
  }

  // ── 9. Build system prompt (no PII — name and industry only) ─────────────
  const systemPrompt = buildAiSystemPrompt(business.name, business.industry);

  // Optionally append the initial auto-text as context so Claude knows
  // what the business already said (still no phone number)
  const fullSystem = firstOutboundBody
    ? systemPrompt + `\n\nThe initial SMS you sent to the customer was:\n"${firstOutboundBody.slice(0, 320)}"`
    : systemPrompt;

  // ── 10. Call Claude — fallback to safe message on any failure ─────────────
  let replyText;
  try {
    if (!anthropic) throw new Error('Anthropic client not initialised');
    const response = await anthropic.messages.create({
      model:      'claude-haiku-4-5-20251001', // fast + cheap for SMS
      max_tokens: 200,
      system:     fullSystem,
      messages:   claudeMessages,
    });
    replyText = response.content[0].text.trim();
    // Hard cap at 320 chars (2 SMS segments) — keeps costs and UX predictable
    if (replyText.length > 320) replyText = replyText.slice(0, 317) + '...';
  } catch (err) {
    // Log error details but send a safe, non-revealing fallback to the customer
    console.error(`[ai-sms] Claude API error | call: ${callId} | ${err.message}`);
    replyText = SMS_FALLBACK;
  }

  // ── 11. Send reply and update rate limiter ────────────────────────────────
  _aiRateLimit.set(from, now);
  await sendAndLogSms(toNumber, from, replyText, callId);
}

// ─── ROUTE 1: Incoming call ───────────────────────────────────────────────────

app.post('/webhook/incoming-call', validateTwilioSignature, (req, res) => {
  const { From: callerNumber, To: toNumber } = req.body;

  if (!isValidPhone(callerNumber) || !isValidPhone(toNumber)) {
    return res.status(400).send('Bad Request');
  }

  const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice">Hi, thanks for calling. We are unable to take your call right now but we will text you back within seconds. Have a great day!</Say>
  <Hangup/>
</Response>`;

  res.type('text/xml').send(twiml);
});

/// ─── ROUTE 2: Call status (fires SMS) ────────────────────────────────────────

const CALLSID_REGEX = /^[A-Za-z0-9]{32,34}$/;

app.post('/webhook/call-status', validateTwilioSignature, async (req, res) => {
  const callSid    = req.body.CallSid;
  const callStatus = req.body.CallStatus;
  const dialCallStatus = req.body.DialCallStatus;

  console.log('Call status debug:', {
    CallStatus: req.body.CallStatus,
    DialCallStatus: req.body.DialCallStatus,
    CallDuration: req.body.CallDuration,
    Duration: req.body.Duration,
    SequenceNumber: req.body.SequenceNumber
  });
  console.log('Call status received — sid:', callSid, 'CallStatus:', callStatus, 'CallDuration:', req.body.CallDuration, 'DialCallStatus:', req.body.DialCallStatus);

  if (!callSid || !CALLSID_REGEX.test(callSid)) {
    return res.status(400).send('Bad Request');
  }

  const { From: callerNumber, To: toNumber } = req.body;

  if (!isValidPhone(callerNumber) || !isValidPhone(toNumber)) {
    return res.status(400).send('Bad Request');
  }

  const status = req.body.CallStatus;
  const callDuration = req.body.CallDuration;

  const isShortCompleted = status === 'completed' && parseInt(callDuration || '0') < 30;
  const isMissed = ['no-answer', 'busy', 'failed'].includes(status);

  if (!isMissed && !isShortCompleted) {
    console.log('[call-status] skipping — not a missed call. status:', status, 'duration:', callDuration);
    return res.sendStatus(200);
  }

  console.log('[call-status] triggering SMS — status:', status, 'duration:', callDuration);

  try {
    await new Promise(resolve => setTimeout(resolve, Math.random() * 500));

    console.log('[call-status] looking up business for number:', req.body.To);
    const { data: bizData, error: bizError } = await supabase
      .from('businesses')
      .select('id, name, industry, custom_sms_template')
      .eq('twilio_number', toNumber)
      .single();
    console.log('[call-status] business lookup result:', bizData ? bizData.name : 'NOT FOUND', bizError ? 'ERROR:' + bizError.message : '');

    const business = (!bizError && bizData) ? bizData : null;
    if (!business) return res.sendStatus(200);

    const { data: call } = await supabase
      .from('calls')
      .insert({
        business_id: business.id,
        caller_number: callerNumber,
        call_sid: callSid,
        status: 'missed',
      })
      .select()
      .single();

    if (!call) {
      console.log('[call-status] duplicate CallSid, skipping:', callSid);
      return res.sendStatus(200);
    }

    console.log('[call-status] calling Claude API...');
    let smsBody;
    try {
      smsBody = await generateSMS(business);
      console.log('[call-status] Claude response received');
    } catch (err) {
      console.error('[call-status] Claude API error:', err.message);
      smsBody = `Hi! Sorry we missed your call at ${safeName(business.name)}. What can we help you with? Reply here and we'll get back to you!`;
    }

    console.log('[call-status] sending SMS to:', req.body.From);
    const result = await twilioClient.messages.create({
      body: smsBody,
      from: toNumber,
      to: callerNumber,
    });
    console.log('[call-status] SMS sent successfully — sid:', result.sid, 'status:', result.status);
    await logMessage(call.id, 'outbound', smsBody);

    res.sendStatus(200);
  } catch (err) {
    console.error('[call-status] FATAL ERROR:', err.message, err.stack);
    res.sendStatus(500);
  }
});

// ─── ROUTE 3: Inbound SMS reply ───────────────────────────────────────────────
// Twilio requires a response within 15 seconds or it retries the webhook.
// We respond immediately with an empty <Response/> then process the AI reply
// asynchronously so we never race that deadline.

app.post('/webhook/sms-reply', validateTwilioSignature, async (req, res) => {
  const { From: from, Body: body, To: to } = req.body;

  if (!isValidPhone(from) || !isValidPhone(to)) return res.status(400).send('Bad Request');

  // Respond to Twilio immediately — AI processing happens in the background
  res.type('text/xml').send('<Response/>');

  // Fire-and-forget: processInboundSms handles logging, rate limiting,
  // injection detection, Claude, and the outbound SMS reply
  processInboundSms(from, body, to).catch(err =>
    console.error(`[sms-reply] unhandled error | from: ${from.slice(0, 6)}*** | ${err.message}`)
  );
});

// ─── ROUTE 4: Mark converted (auth required) ─────────────────────────────────

app.post('/api/calls/:callId/convert', requireAuth, async (req, res) => {
  if (!isValidUUID(req.params.callId)) return res.status(400).json({ error: 'Invalid ID' });
  await updateCallStatus(req.params.callId, 'converted');
  res.json({ success: true });
});

// ─── ROUTE: Owner reply to customer ──────────────────────────────────────────
// Sends an SMS from the business owner directly to the customer and logs it.

app.post('/api/calls/:callId/reply', requireAuth, async (req, res) => {
  if (!isValidUUID(req.params.callId)) return res.status(400).json({ error: 'Invalid ID' });

  const { message } = req.body;
  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'Message is required' });
  }
  const body = message.trim().slice(0, 1600);

  // Get call to confirm it exists and get the customer number
  const { data: call, error: callError } = await supabase
    .from('calls')
    .select('id, caller_number, business_id')
    .eq('id', req.params.callId)
    .single();

  if (callError || !call) return res.status(404).json({ error: 'Call not found' });

  // Verify the business belongs to the requesting user (ownership check)
  const email = req.headers['x-user-email'];
  const { data: biz } = await supabase
    .from('businesses')
    .select('id, twilio_number')
    .eq('id', call.business_id)
    .eq('email', email)
    .single();

  if (!biz) return res.status(403).json({ error: 'Forbidden' });

  // Send SMS via Twilio
  try {
    const from = biz.twilio_number || process.env.TWILIO_PHONE_NUMBER;
    await twilioClient.messages.create({ body, from, to: call.caller_number });
    console.log(`[owner-reply] SMS sent | call: ${call.id} | to: ${maskPhone(call.caller_number)}`);
  } catch (err) {
    console.error('[owner-reply] Twilio error:', err.message);
    return res.status(500).json({ error: 'Failed to send SMS' });
  }

  // Log in messages table
  const { data: msg, error: msgError } = await supabase
    .from('messages')
    .insert({ call_id: call.id, direction: 'outbound', sent_by: 'owner', body })
    .select('id, sent_at')
    .single();

  if (msgError) console.error('[owner-reply] message log failed:', msgError.message);

  res.json({ success: true, message: msg || null });
});

// ─── ROUTE 5: Get calls for business (auth required) ─────────────────────────

app.get('/api/businesses/:businessId/calls', requireAuth, async (req, res) => {
  if (!isValidUUID(req.params.businessId)) return res.status(400).json({ error: 'Invalid ID' });

  const { data, error } = await supabase
    .from('calls')
    .select('id, caller_number, caller_name, status, created_at, messages(id, direction, body, sent_by, sent_at)')
    .eq('business_id', req.params.businessId)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: 'Internal server error' }); // never leak DB errors
  res.json(data);
});

// ─── ROUTE 6: Health check ────────────────────────────────────────────────────

app.get('/health',            (req, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.get('/healthz',           (req, res) => res.status(200).send('ok'));
// Dashboard pre-flight check — no auth, no rate limiting, just confirms the
// server is reachable before the dashboard spends 8s waiting on /api/my-business
app.get('/api/health-check', (req, res) => res.json({ ok: true }));

// ─── ROUTE: Test call TwiML ──────────────────────────────────────────────────
// Twilio fetches this URL when placing a test call. Returns the spoken message.

app.post('/webhook/test-twiml', validateTwilioSignature, (req, res) => {
  const twiml = `<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="alice">This is a test from CallBack AI. Your setup is working correctly. Goodbye!</Say>
  <Hangup/>
</Response>`;
  res.type('text/xml').send(twiml);
});

// ─── ROUTE: Test call ────────────────────────────────────────────────────────
// No auth required — takes { phone } from body, places a Twilio call to that
// number, plays a short TwiML message, then fires the initial missed-call SMS
// directly (8 s delay so the SMS arrives just after the call ends).
//
// We trigger the SMS manually rather than relying on the call-status webhook
// because the webhook's business lookup uses the "To" field (the number that
// received the call) — which for an outbound test call is the owner's real
// phone, not their Twilio number.

app.post('/api/test-call', async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: 'Missing phone' });

  const cleanPhone = String(phone).replace(/\s/g, '');
  if (!isValidPhone(cleanPhone)) return res.status(400).json({ error: 'Invalid phone number' });

  // Look up the business by owner phone so we can call from their dedicated number
  const { data: biz } = await supabase
    .from('businesses')
    .select('id, name, industry, twilio_number, custom_sms_template')
    .eq('phone', cleanPhone)
    .maybeSingle();

  const fromNumber = biz?.twilio_number || process.env.TWILIO_PHONE_NUMBER;

  try {
    const twiml = '<?xml version="1.0" encoding="UTF-8"?><Response><Say voice="alice">This is a test from CallBack AI. Your setup is working. You will now receive a text message.</Say><Hangup/></Response>';
    await twilioClient.calls.create({ twiml, to: cleanPhone, from: fromNumber });
    console.log(`[test-call] call placed to ${maskPhone(cleanPhone)}`);

    // Fire the initial missed-call SMS ~8 s after the call so it arrives naturally
    if (biz) {
      setTimeout(async () => {
        try {
          const smsBody = await generateSMS(biz);
          await twilioClient.messages.create({ body: smsBody, from: fromNumber, to: cleanPhone });
          console.log(`[test-call] SMS sent to ${maskPhone(cleanPhone)}`);
        } catch (err) {
          console.error('[test-call] SMS error:', err.message);
        }
      }, 8000);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('[test-call] error:', err.message);
    res.status(500).json({ error: 'Failed to place call' });
  }
});

// ─── ROUTE: Lookup provisioned number by email (no auth) ─────────────────────
// Called by the onboarding page after a Stripe redirect to get the Twilio number
// the Stripe webhook just assigned. Returns null if provisioning hasn't finished yet
// — the client polls until it gets a number or times out.

app.get('/api/lookup-number', async (req, res) => {
  const { email } = req.query;
  if (!email || !isValidEmail(email)) return res.json({ twilio_number: null });
  const { data } = await supabase
    .from('businesses')
    .select('twilio_number')
    .eq('email', email)
    .maybeSingle();
  res.json({ twilio_number: data?.twilio_number || null });
});

// ─── ROUTE: Onboard new business ─────────────────────────────────────────────
// Creates a Stripe Checkout Session and returns the hosted URL.
// Actual provisioning (Twilio number, Supabase record, welcome email) happens
// in /webhook/stripe once Stripe confirms payment via checkout.session.completed.

app.post('/api/onboard', async (req, res) => {
  const { email, businessName, industry, phone, clerkUserId } = req.body;

  if (!email || !businessName || !phone) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (typeof businessName !== 'string' || businessName.length > 200) {
    return res.status(400).json({ error: 'Invalid business name' });
  }
  const cleanPhone = String(phone).replace(/\s/g, '');
  if (!isValidPhone(cleanPhone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  const bizName = safeName(businessName);
  console.log(`[onboard] creating checkout session | biz: "${bizName}" | email: ${maskEmail(email)}`);

  try {
    const session = await stripe.checkout.sessions.create({
      mode:              'subscription',
      customer_email:    email,
      line_items: [{
        price:    process.env.STRIPE_PRICE_ID,
        quantity: 1,
      }],
      subscription_data: { trial_period_days: 14 },
      success_url:       'https://callbackai.ie/callback-onboarding.html?success=true',
      cancel_url:        'https://callbackai.ie/callback-onboarding.html?cancelled=true',
      metadata: {
        businessName: bizName,
        industry:     isValidIndustry(industry) ? industry : 'general',
        phone:        cleanPhone,
        email,
        clerkUserId:  clerkUserId || '',
      },
    });

    console.log(`[onboard] checkout session created: ${session.id}`);
    return res.json({ url: session.url });

  } catch (err) {
    console.error(`[onboard] checkout session failed: ${err.message}`);
    return res.status(500).json({ error: 'Could not create checkout session. Please try again.' });
  }
});

// ─── ROUTE: Get business by email (Clerk dashboard auth) ─────────────────────

app.get('/api/my-business', requireAuth, async (req, res) => {
  try {
    const email = req.headers['x-user-email'];
    console.log('[/api/my-business] lookup:', email ? email.slice(0,3) + '***' : 'NO EMAIL');

    if (!email) return res.status(400).json({ error: 'No email header' });

    const { data, error } = await supabase
      .from('businesses')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !data) {
      console.log('[/api/my-business] NOT FOUND for email');
      return res.status(404).json({ error: 'Business not found' });
    }

    console.log('[/api/my-business] FOUND:', data.id, data.business_name);
    return res.json(data);

  } catch (err) {
    console.error('[/api/my-business] CRASH:', err.message);
    return res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ─── ROUTE: Mark setup as complete (Clerk dashboard auth) ────────────────────
// Called when the client clicks "I've set up call forwarding" on the setup banner.

app.post('/api/my-business/setup-complete', requireAuth, async (req, res) => {
  const email = req.headers['x-user-email'];
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Missing email' });
  }
  const { error } = await supabase
    .from('businesses')
    .update({ setup_completed: true })
    .eq('email', email);

  if (error) {
    console.error(`[setup-complete] DB error for ${maskEmail(email)}:`, error.message);
    return res.status(500).json({ error: 'Failed to update' });
  }
  console.log(`[setup-complete] marked done for ${maskEmail(email)}`);
  res.json({ success: true });
});

// ─── Catch-all 404 ────────────────────────────────────────────────────────────

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ─── Global error handler ─────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' }); // never expose stack traces
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
console.log(`[startup] binding to 0.0.0.0:${PORT}...`);
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`\nCallBack AI on port ${PORT}`);
  console.log(`   ✓ Twilio signature validation (active)`);
  console.log(`   ✓ API Bearer token auth`);
  console.log(`   ✓ Rate limiting (active)`);
  console.log(`   ✓ Input validation & sanitisation`);
  console.log(`   ✓ Security headers (Helmet)`);
  console.log(`   ✓ Env var validation at startup\n`);
});

// Catch errors binding the port (e.g. EADDRINUSE) — without this the error
// is an uncaught exception that would previously produce no log output.
server.on('error', (err) => {
  console.error(`[startup] server failed to start on port ${PORT}:`, err.message);
  process.exit(1);
});
