# CallBack AI

Missed-call recovery for small businesses. When a call goes unanswered, CallBack AI texts the caller back automatically, holds the SMS conversation with Claude, and logs everything to a dashboard so the owner can see which missed calls turned into jobs.

**Live:** [callbackai.ie](https://callbackai.ie)

## How it works

1. A customer calls the business and nobody picks up.
2. Twilio reports the missed call to `/webhook/call-status`, and the server texts the caller. The opening message is a short, industry-specific template (or the business's custom one), so it goes out with no AI delay.
3. When the caller replies, `/webhook/sms-reply` hands the message to Claude (Haiku). The server rate-limits replies per caller, screens for prompt injection, caps replies at 2 SMS segments and falls back to a safe message if the API call fails.
4. The owner is notified by SMS and sees every call and conversation in the dashboard, where they can reply manually or mark a call as converted.

## Stack

| Layer | Tech |
|---|---|
| Server | Node.js, Express (hosted on Railway) |
| Telephony / SMS | Twilio |
| AI replies | Anthropic API (Claude Haiku 4.5) |
| Database | Supabase |
| Auth | Clerk |
| Billing | Stripe (subscriptions + customer portal) |
| Email | Resend |
| Frontend | Static HTML pages (landing, onboarding, dashboard) |
| Hardening | Helmet, rate limiting, Twilio signature validation, Stripe webhook verification |

## Repo layout

```
callback-webhook-server.js   Express server: Twilio/Stripe webhooks + dashboard API
index.html                   Landing page
callback-landing.html        Landing page (variant)
callback-onboarding.html     Sign-up and business setup flow
callback-dashboard.html      Owner dashboard
package.json
```

## API overview

| Route | Purpose |
|---|---|
| `POST /webhook/incoming-call`, `/webhook/call-status`, `/webhook/sms-reply` | Twilio webhooks (signature-validated) |
| `POST /webhook/stripe` | Stripe billing events |
| `POST /api/onboard` | Create a business and provision its number |
| `GET /api/my-business`, `POST /api/my-business/setup-complete` | Business profile (auth required) |
| `GET /api/businesses/:id/calls` | Call history (auth required) |
| `POST /api/calls/:id/reply`, `/api/calls/:id/convert` | Manual reply / mark converted (auth required) |
| `POST /api/create-portal-session` | Stripe customer portal |
| `GET /health` | Health check |

## Running locally

```bash
npm install
npm run dev   # needs a .env file with the variables below
```

Environment variables read by the server:

```
ANTHROPIC_API_KEY
CLERK_SECRET_KEY
RESEND_API_KEY
STRIPE_SECRET_KEY  STRIPE_WEBHOOK_SECRET  STRIPE_PRICE_ID
SUPABASE_URL  SUPABASE_SERVICE_KEY
TWILIO_ACCOUNT_SID  TWILIO_AUTH_TOKEN  TWILIO_PHONE_NUMBER
RAILWAY_URL  PORT
```

Twilio needs a public URL to reach the webhooks, so use a tunnel such as ngrok when developing locally.
