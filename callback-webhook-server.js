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

require('dotenv').config();
const express   = require('express');
const twilio    = require('twilio');
const Anthropic = require('@anthropic-ai/sdk');
const { createClient } = require('@supabase/supabase-js');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');

// ─── [FIX 1] Validate all required env vars on startup ───────────────────────
// Fail immediately if any secret is missing — never run half-configured.

const REQUIRED_ENV = [
  'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER',
  'ANTHROPIC_API_KEY', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'API_SECRET',
];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length > 0) {
  console.error(`Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

// ─── App setup ────────────────────────────────────────────────────────────────

const app = express();
app.set('trust proxy', 1);

// Security headers — blocks XSS, clickjacking, MIME sniffing, etc.
app.use(helmet());
app.disable('x-powered-by');

// Rate limiting — prevents SMS bombing and brute force
const webhookLimiter = rateLimit({ windowMs: 60_000, max: 60 });
const apiLimiter     = rateLimit({ windowMs: 60_000, max: 30 });
app.use('/webhook', webhookLimiter);
app.use('/api',     apiLimiter);

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '10kb' }));

// ─── Clients ─────────────────────────────────────────────────────────────────

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const anthropic    = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
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

// ─── [FIX 5] API Bearer token auth middleware ─────────────────────────────────
// All /api routes require Authorization: Bearer <API_SECRET>.
// Uses constant-time comparison to prevent timing attacks.

function requireApiAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token || token.length > 512) return res.status(401).json({ error: 'Unauthorised' });

  const expected = Buffer.from(process.env.API_SECRET);
  const provided = Buffer.from(token);

  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
    console.warn(`Failed API auth from ${req.ip}`);
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ─── [FIX 6] Input validation ────────────────────────────────────────────────
// Validate and sanitise all external input before use.

const E164_REGEX = /^\+[1-9]\d{7,14}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const isValidPhone    = n  => typeof n === 'string' && E164_REGEX.test(n.trim());
const isValidUUID     = id => typeof id === 'string' && UUID_REGEX.test(id);
const isValidIndustry = i  => Object.keys(INDUSTRY_TONES).includes(i);
const safeName        = s  => String(s || '').slice(0, 100).replace(/[<>"']/g, '');

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

app.post('/webhook/sms-reply', validateTwilioSignature, async (req, res) => {
  const { From: from, Body: body } = req.body;

  if (!isValidPhone(from)) return res.status(400).send('Bad Request');

  const safeBody = String(body || '').slice(0, 1600); // max SMS length

  const { data: calls } = await supabase
    .from('calls').select('id')
    .eq('caller_number', from)
    .order('created_at', { ascending: false }).limit(1);

  if (calls?.length > 0) {
    await logMessage(calls[0].id, 'inbound', safeBody);
    await updateCallStatus(calls[0].id, 'replied');
  }

  res.type('text/xml').send('<Response/>');
});

// ─── ROUTE 4: Mark converted (auth required) ─────────────────────────────────

app.post('/api/calls/:callId/convert', requireApiAuth, async (req, res) => {
  if (!isValidUUID(req.params.callId)) return res.status(400).json({ error: 'Invalid ID' });
  await updateCallStatus(req.params.callId, 'converted');
  res.json({ success: true });
});

// ─── ROUTE 5: Get calls for business (auth required) ─────────────────────────

app.get('/api/businesses/:businessId/calls', requireApiAuth, async (req, res) => {
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

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ─── Catch-all 404 ────────────────────────────────────────────────────────────

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ─── Global error handler ─────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' }); // never expose stack traces
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nCallBack AI on port ${PORT}`);
  console.log(`   ✓ Twilio signature validation (active)`);
  console.log(`   ✓ API Bearer token auth`);
  console.log(`   ✓ Rate limiting (active)`);
  console.log(`   ✓ Input validation & sanitisation`);
  console.log(`   ✓ Security headers (Helmet)`);
  console.log(`   ✓ Env var validation at startup\n`);
});
