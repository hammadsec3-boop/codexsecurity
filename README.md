# Codex Security — Free SSL Test tool

A small, self-hosted SSL/TLS checker for codexsecurity.co, in the spirit of
ssllabs.com: a visitor types in a domain, the tool connects to it on port
443, reads back the certificate/protocol/cipher, and shows an instant A–F
grade. Every test also emails a short lead report to your team.

## What's in this folder

```
api/ssl-check.js     Backend — Vercel serverless function, Node.js, no npm installs needed
public/ssl-test.html The tool's page (matches the existing site's dark/gold theme)
public/styles.css    Copy of the site's shared stylesheet
```

## How to add it to the existing codexsecurity-pied.vercel.app project

Hand this to your developer — it drops straight into the existing Vercel
project, no new infrastructure needed:

1. Copy `api/ssl-check.js` into the project's existing `/api` folder.
2. Copy `public/ssl-test.html` into wherever the other pages live (next to
   `index.html`, `services.html`, etc.) — use the project's existing
   `styles.css` instead of the copy here, since it's identical.
3. Add a "Free SSL Test" link to the site's navigation, pointing at
   `ssl-test.html`.
4. Deploy. Vercel automatically turns any file under `/api` into a live
   endpoint — `api/ssl-check.js` becomes `/api/ssl-check` with no extra
   config.

## Turning on the email notification

Right now, if no email service is configured, every test just gets logged
instead of emailed — nothing breaks, you just won't get notified. To get
the email to **contact@codexsecurity.co**:

1. Create a free account at [resend.com](https://resend.com) (3,000
   emails/month free, plenty for this).
2. Verify your domain `codexsecurity.co` there (adds a couple of DNS
   records — your developer or domain registrar can do this in a few
   minutes).
3. In Resend, create an API key.
4. In Vercel → your project → **Settings → Environment Variables**, add:
   - `RESEND_API_KEY` — the key from step 3
   - `FROM_EMAIL` — e.g. `Codex Security Tools <tools@codexsecurity.co>`
     (must be on the verified domain)
   - `NOTIFY_EMAIL` — `contact@codexsecurity.co` (optional — this is
     already the default if you skip it)
5. Redeploy. From then on, every test sends you an email with the domain
   tested, the grade, and a breakdown — so you can follow up with anyone
   who gets a C or below.

No Resend account yet? The tool still works for visitors; you just won't
get the email until it's set up. Skipping Resend entirely and using a
different email API (SendGrid, Postmark, etc.) only means rewriting the
`notifyTeam` function in `api/ssl-check.js` — everything else stays the
same.

## What the grade actually checks

Loosely modelled on Qualys SSL Labs' public methodology (not identical to
it — a from-scratch rubric kept simple on purpose):

- **Protocol** (30%) — TLS 1.3 and 1.2 score well; TLS 1.1/1.0 are marked
  outdated; anything older fails.
- **Cipher strength** (30%) — modern AEAD ciphers (GCM, ChaCha20-Poly1305)
  score well; CBC-mode ciphers are marked as ageing; RC4/DES/export-grade
  ciphers fail.
- **Certificate** (30%) — checks the chain is trusted, the hostname
  matches, and how many days remain before expiry. An expired certificate
  caps the whole grade at F; an untrusted chain caps it at C, no matter how
  good the rest looks — same spirit as SSL Labs' own caps.
- **HSTS header** (10%) — rewards sites that force HTTPS with a long
  `max-age`.

## Security notes (already handled, for your developer's awareness)

- **SSRF protection**: before connecting anywhere, the function resolves
  the domain and refuses to proceed if it points at a private, loopback,
  link-local, or cloud-metadata address (`169.254.169.254` etc.). Without
  this, the tool could be abused to probe internal infrastructure.
- **Basic rate limiting**: a lightweight per-IP limiter (8 tests/minute) is
  built in to slow down casual abuse. It resets whenever the serverless
  instance recycles, so it's a speed bump, not a hard wall — if the tool
  gets heavy traffic, swap it for Upstash Redis or Vercel's own rate
  limiting.
- **Timeouts**: every outbound connection has an 8-second timeout, so one
  slow or unresponsive target can't hang the function.

## Testing it yourself

Once deployed, visit `/ssl-test.html` and try a few real domains —
google.com should come back A/A+, and an old self-signed test server (if
you have one) should come back with a clearly marked failure. This couldn't
be tested live from inside the sandbox this was built in (no direct
internet access to arbitrary hosts), so give it a real run after deploying.
