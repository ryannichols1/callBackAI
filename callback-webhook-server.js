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

// Graceful shutdown on SIGTERM (Railway sends this before every new deployment
// and when a health check fails). Without this handler Node.js exits immediately
// which Railway can interpret as unhealthy and trigger a restart loop.
process.on('SIGTERM', () => {
  console.log('[shutdown] SIGTERM received — closing server gracefully');
  if (typeof server !== 'undefined') {
    server.close(() => {
      console.log('[shutdown] HTTP server closed');
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
  'STRIPE_SECRET_KEY', 'STRIPE_PRICE_ID', 'CLERK_SECRET_KEY',
  // NOTE: API_SECRET removed — requireApiAuth was replaced by Clerk JWT auth
  // and process.env.API_SECRET is no longer referenced anywhere in the codebase.
  // Keeping it here would crash the server if it's not set in Railway env vars.
];
// Log all env var names (NOT values) so Railway logs show what is/isn't set
console.log('[startup] env vars present:', REQUIRED_ENV.filter(k => !!process.env[k]).join(', '));
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length > 0) {
  console.error(`STARTUP FAILED — missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

const express   = require('express');
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
  origin: ['https://callbackai.netlify.app', 'http://localhost:3000'],
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Email'],
}));

// Rate limiting — prevents SMS bombing and brute force
const webhookLimiter  = rateLimit({ windowMs: 60_000,      max: 60 });
const apiLimiter      = rateLimit({ windowMs: 60_000,      max: 30 });
const onboardLimiter  = rateLimit({ windowMs: 60 * 60_000, max: 5  }); // 5 signups/hr/IP
app.use('/webhook',       webhookLimiter);
app.use('/api',           apiLimiter);
app.use('/api/onboard',   onboardLimiter);

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

const supabase     = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

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

  // Irish carrier call-forwarding instructions
  const forwardingInstructions = `
HOW TO SET UP CALL FORWARDING (takes 2 minutes):

Your CallBack AI number: ${displayNumber}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VODAFONE IRELAND
Open My Vodafone app → My Plan → Call settings → Divert calls
→ "When unanswered" → enter ${displayNumber}

THREE IRELAND
Open My3 app → Account → Call settings → Call divert
→ "No answer" → enter ${displayNumber}

EIR
Dial this from your phone: *61*${displayNumber}#

LANDLINE / OTHER NETWORKS
Dial this from your phone: **61*${displayNumber}#
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Once set up, any missed call will automatically get a CallBack AI text.
Your dashboard: https://callbackai.netlify.app/callback-dashboard.html
  `.trim();

  const htmlBody = `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:24px">
  <h1 style="color:#16120e;font-size:24px;margin-bottom:4px">You're live on CallBack AI!</h1>
  <p style="color:#666;margin-bottom:32px">Welcome, ${safeName(bizName)}. Follow the steps below to start recovering missed calls.</p>

  <div style="background:#f5f5f5;border-radius:8px;padding:20px;margin-bottom:24px;text-align:center">
    <p style="color:#666;font-size:13px;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Your CallBack AI number</p>
    <p style="font-size:28px;font-weight:700;color:#ff4d1c;letter-spacing:.05em;margin:0">${displayNumber}</p>
  </div>

  <h2 style="color:#16120e;font-size:16px;margin-bottom:12px">Set up call forwarding (2 minutes)</h2>
  <p style="color:#666;font-size:14px;margin-bottom:16px">Forward missed calls from your business number to your CallBack AI number:</p>

  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:24px">
    <tr style="background:#16120e;color:#fff">
      <th style="padding:10px 14px;text-align:left;border-radius:6px 0 0 0">Network</th>
      <th style="padding:10px 14px;text-align:left;border-radius:0 6px 0 0">Instructions</th>
    </tr>
    <tr style="background:#fff;border-bottom:1px solid #eee">
      <td style="padding:10px 14px;font-weight:600">Vodafone Ireland</td>
      <td style="padding:10px 14px">My Vodafone app → My Plan → Call settings → Divert calls → <em>When unanswered</em> → enter <strong>${displayNumber}</strong></td>
    </tr>
    <tr style="background:#fafafa;border-bottom:1px solid #eee">
      <td style="padding:10px 14px;font-weight:600">Three Ireland</td>
      <td style="padding:10px 14px">My3 app → Account → Call settings → Call divert → <em>No answer</em> → enter <strong>${displayNumber}</strong></td>
    </tr>
    <tr style="background:#fff;border-bottom:1px solid #eee">
      <td style="padding:10px 14px;font-weight:600">Eir</td>
      <td style="padding:10px 14px">Dial from your phone: <code style="background:#f0f0f0;padding:2px 6px;border-radius:3px">*61*${displayNumber}#</code></td>
    </tr>
    <tr style="background:#fafafa">
      <td style="padding:10px 14px;font-weight:600">Landline / Other</td>
      <td style="padding:10px 14px">Dial from your phone: <code style="background:#f0f0f0;padding:2px 6px;border-radius:3px">**61*${displayNumber}#</code></td>
    </tr>
  </table>

  <p style="color:#666;font-size:13px;margin-bottom:24px">Once set up, every missed call will get an automatic CallBack AI text within seconds.</p>

  <a href="https://callbackai.netlify.app/callback-dashboard.html"
     style="display:inline-block;background:#ff4d1c;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px">
    Open Your Dashboard
  </a>
</div>`;

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: 'CallBack AI <hello@callbackai.app>',
        to:   [toEmail],
        subject: "You're live on CallBack AI",
        html: htmlBody,
        text: forwardingInstructions,
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
  const tone     = INDUSTRY_TONES[industry];
  const name     = safeName(business.name);

  if (business.custom_sms_template) {
    return business.custom_sms_template.slice(0, 320).replace('{{business_name}}', name);
  }

  // Caller number intentionally NOT passed to Claude — no need to expose it
  const prompt = `${tone}

A customer just called ${name} and the call went unanswered.

Write a SHORT, warm SMS reply (max 55 words).
- Apologise for missing the call
- Ask what they need help with
- Feel human, not robotic
- End with a clear invitation to reply

Return ONLY the SMS text. No quotes, no preamble.`;

  if (!anthropic) throw new Error('Anthropic client not initialised');
  const response = await anthropic.messages.create({
    model: 'claude-sonnet-4-20250514', max_tokens: 120,
    messages: [{ role: 'user', content: prompt }],
  });
  return response.content[0].text.trim();
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
const SMS_FALLBACK = "Thanks for getting back to us — we'll have someone call you shortly.";

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

  return `You are a helpful AI assistant for ${name}, ${industryDesc}.

A customer called ${name} and the call went unanswered. An automatic SMS was sent to apologise. The customer has now replied and you are continuing the conversation on behalf of ${name}.

YOUR ROLE:
- Respond warmly and helpfully on behalf of ${name}
- Gather the details needed to help — what the customer needs, when they are available, any relevant specifics (type of job, location, party size, etc.)
- Guide the conversation toward a clear next step
- Keep every reply SHORT — this is SMS, not email. Maximum 2–3 sentences.
- Always end with a question or a clear next step

TONE: ${INDUSTRY_TONES[industry]}

STRICT RULES — follow these without exception:
1. NEVER make specific promises about pricing, timelines, or availability
2. If the customer asks directly whether they are speaking to a human or an AI, be honest: say you are an AI assistant for ${name} and that a team member will follow up personally
3. NEVER discuss anything unrelated to helping this customer with their enquiry
4. NEVER mention competitor businesses
5. If the customer is ready to book, wants a quote, or the situation is complex, end your reply with: "I'll make sure the team at ${name} gets back to you directly to sort everything out — does that work for you?"
6. Read the full conversation history and move it forward — do NOT repeat yourself
7. Do NOT invent facts about the business (hours, prices, staff names, policies)`;
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

  const wasMissed =
    ['no-answer', 'busy', 'failed'].includes(callStatus) ||
    ['no-answer', 'busy', 'failed'].includes(dialCallStatus) ||
    (callStatus === 'completed' && dialCallStatus === undefined);
  if (!wasMissed) return res.type('text/xml').send('<Response/>');

  await new Promise(resolve => setTimeout(resolve, Math.random() * 500));

  const business = await getBusinessByTwilioNumber(toNumber);
  if (!business) return res.type('text/xml').send('<Response/>');

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
    console.log('Duplicate CallSid, skipping:', callSid);
    return res.type('text/xml').send('<Response/>');
  }

  let smsBody;
  try {
    smsBody = await generateSMS(business);
  } catch (err) {
    console.error('Claude API error:', err.message);
    smsBody = `Hi! Sorry we missed your call at ${safeName(business.name)}. What can we help you with? Reply here and we'll get back to you!`;
  }

  try {
    const result = await twilioClient.messages.create({
      body: smsBody,
      from: toNumber,
      to: callerNumber,
    });
    console.log('SMS sent — sid:', result.sid, 'status:', result.status);
    if (call) await logMessage(call.id, 'outbound', smsBody);
  } catch (err) {
    console.error('Twilio SMS error:', err.code, err.message);
  }

  res.type('text/xml').send('<Response/>');
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

// ─── ROUTE 5: Get calls for business (auth required) ─────────────────────────

app.get('/api/businesses/:businessId/calls', requireAuth, async (req, res) => {
  if (!isValidUUID(req.params.businessId)) return res.status(400).json({ error: 'Invalid ID' });

  const { data, error } = await supabase
    .from('calls')
    .select('id, caller_number, caller_name, status, created_at, messages(id, direction, body, sent_at)')
    .eq('business_id', req.params.businessId)
    .order('created_at', { ascending: false })
    .limit(50);

  if (error) return res.status(500).json({ error: 'Internal server error' }); // never leak DB errors
  res.json(data);
});

// ─── ROUTE 6: Health check ────────────────────────────────────────────────────

app.get('/health',            (req, res) => res.json({ ok: true, time: new Date().toISOString() }));
// Dashboard pre-flight check — no auth, no rate limiting, just confirms the
// server is reachable before the dashboard spends 8s waiting on /api/my-business
app.get('/api/health-check', (req, res) => res.json({ ok: true }));

// ─── ROUTE: Test call ────────────────────────────────────────────────────────

app.post('/api/test-call', async (req, res) => {
  const { phone } = req.body;

  if (!isValidPhone(phone.replace(/\s/g, ''))) {
    return res.status(400).json({ error: 'Invalid phone' });
  }

  try {
    await twilioClient.calls.create({
      url: 'https://callbackai-production.up.railway.app/webhook/incoming-call',
      to: phone.replace(/\s/g, ''),
      from: process.env.TWILIO_PHONE_NUMBER,
    });

    res.json({ success: true });
  } catch(err) {
    console.error('Test call error:', err.message);
    res.status(500).json({ error: 'Failed to place call' });
  }
});

// ─── ROUTE: Onboard new business ─────────────────────────────────────────────
// Full self-serve provisioning flow:
//   1. Idempotency check (return existing record if email already onboarded)
//   2. Create Stripe customer + subscription
//   3. Provision a unique Irish Twilio number (+353)
//   4. Configure the number's voice + SMS webhooks to point at this server
//   5. Insert Supabase record
//   6. Send welcome email with the number + forwarding instructions
//
// On any failure after Stripe is charged we cancel the subscription, delete
// the Stripe customer, and release the Twilio number so the client isn't
// left in a broken state and isn't billed.

const RAILWAY_URL = process.env.RAILWAY_URL || 'https://callbackai-production.up.railway.app';

app.post('/api/onboard', async (req, res) => {
  const { paymentMethodId, business, clerkUserId } = req.body;

  // ── Input validation ─────────────────────────────────────────────────────
  if (!paymentMethodId || !business?.name || !business?.email || !business?.phone) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  if (!isValidPmId(paymentMethodId)) {
    return res.status(400).json({ error: 'Invalid payment method' });
  }
  if (!isValidEmail(business.email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (typeof business.name !== 'string' || business.name.length > 200) {
    return res.status(400).json({ error: 'Invalid business name' });
  }
  const cleanPhone = business.phone.replace(/\s/g, '');
  if (!isValidPhone(cleanPhone)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }

  const bizName = safeName(business.name);
  console.log(`[onboard] start | biz: "${bizName}" | email: ${maskEmail(business.email)} | phone: ${maskPhone(cleanPhone)}`);

  // ── Idempotency: if this email is already a client, return the existing record ──
  // Prevents double-charging if the form is submitted twice.
  const { data: existing } = await supabase
    .from('businesses')
    .select('id, twilio_number, stripe_subscription_id')
    .eq('email', business.email)
    .maybeSingle();

  if (existing) {
    console.log(`[onboard] idempotent — "${bizName}" already exists (id: ${existing.id})`);
    return res.json({
      success: true,
      businessId: existing.id,
      twilioNumber: existing.twilio_number,
      alreadyExists: true,
    });
  }

  // Resources to clean up if anything goes wrong after they're created
  let customer      = null;
  let subscription  = null;
  let twilioSid     = null; // Twilio IncomingPhoneNumber SID for release on failure

  try {
    // ── Step 1: Stripe ───────────────────────────────────────────────────────
    console.log(`[onboard] step 1/5: creating Stripe customer for "${bizName}"`);
    customer = await stripe.customers.create({
      email:            business.email,
      name:             bizName,
      phone:            cleanPhone,
      payment_method:   paymentMethodId,
      invoice_settings: { default_payment_method: paymentMethodId },
      metadata:         { industry: business.industry || 'general' },
    });

    subscription = await stripe.subscriptions.create({
      customer:          customer.id,
      items:             [{ price: process.env.STRIPE_PRICE_ID }],
      trial_period_days: 14,
      payment_settings:  {
        payment_method_types:             ['card'],
        save_default_payment_method:      'on_subscription',
      },
    });
    console.log(`[onboard] step 1/5: Stripe OK — sub: ${subscription.id}`);

    // ── Step 2: Search for an available Irish number ─────────────────────────
    console.log(`[onboard] step 2/5: searching for available +353 Twilio number`);
    const available = await twilioClient
      .availablePhoneNumbers('IE')
      .local.list({ limit: 5 });

    if (!available.length) {
      throw new Error('No Irish (+353) Twilio numbers are currently available. Please try again in a few minutes.');
    }
    const selectedNumber = available[0].phoneNumber;
    console.log(`[onboard] step 2/5: found number ${maskPhone(selectedNumber)}`);

    // ── Step 3: Purchase and configure the number ────────────────────────────
    console.log(`[onboard] step 3/5: purchasing ${maskPhone(selectedNumber)}`);
    const purchased = await twilioClient.incomingPhoneNumbers.create({
      phoneNumber: selectedNumber,
      voiceUrl:    `${RAILWAY_URL}/webhook/incoming-call`,
      voiceMethod: 'POST',
      smsUrl:      `${RAILWAY_URL}/webhook/sms-reply`,
      smsMethod:   'POST',
      friendlyName: `CallBackAI — ${bizName}`,
    });
    twilioSid = purchased.sid;
    console.log(`[onboard] step 3/5: Twilio number purchased | sid: ${twilioSid}`);

    // ── Step 4: Create the Supabase record ───────────────────────────────────
    console.log(`[onboard] step 4/5: inserting Supabase record for "${bizName}"`);
    const { data: newBusiness, error: dbError } = await supabase
      .from('businesses')
      .insert({
        name:                  bizName,
        industry:              isValidIndustry(business.industry) ? business.industry : 'general',
        phone:                 cleanPhone,
        email:                 business.email,
        twilio_number:         selectedNumber,
        clerk_user_id:         clerkUserId || null,
        stripe_customer_id:    customer.id,
        stripe_subscription_id: subscription.id,
        trial_ends_at:         new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
        setup_completed:       false,
        status:                'active',
      })
      .select('id')
      .single();

    if (dbError) {
      throw new Error(`Supabase insert failed: ${dbError.message}`);
    }
    console.log(`[onboard] step 4/5: Supabase OK — business id: ${newBusiness.id}`);

    // ── Step 5: Send welcome email ───────────────────────────────────────────
    console.log(`[onboard] step 5/5: sending welcome email to ${maskEmail(business.email)}`);
    // Fire-and-forget — never let email failure block the success response
    sendWelcomeEmail(business.email, bizName, selectedNumber).catch(err =>
      console.error('[onboard] welcome email failed:', err.message)
    );

    console.log(`[onboard] complete — "${bizName}" | id: ${newBusiness.id}`);
    return res.json({
      success:        true,
      businessId:     newBusiness.id,
      twilioNumber:   selectedNumber,
      trialEndsAt:    subscription.trial_end,
      subscriptionId: subscription.id,
    });

  } catch (err) {
    console.error(`[onboard] FAILED for "${bizName}": ${err.message}`);

    // Clean up in reverse order of creation so no orphaned resources remain
    if (twilioSid) {
      await twilioClient.incomingPhoneNumbers(twilioSid).remove().catch(e =>
        console.error('[onboard] cleanup: could not release Twilio number:', e.message)
      );
    }
    if (subscription) {
      await stripe.subscriptions.cancel(subscription.id).catch(e =>
        console.error('[onboard] cleanup: could not cancel subscription:', e.message)
      );
    }
    if (customer && !subscription) {
      await stripe.customers.del(customer.id).catch(e =>
        console.error('[onboard] cleanup: could not delete Stripe customer:', e.message)
      );
    }

    if (err.type === 'StripeCardError') {
      return res.status(400).json({ error: err.message });
    }
    // Expose a specific message for the "no numbers available" case
    if (err.message?.startsWith('No Irish')) {
      return res.status(503).json({ error: err.message });
    }
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
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
      .eq('owner_email', email)
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
console.log(`[startup] binding to port ${PORT}...`);
const server = app.listen(PORT, () => {
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
