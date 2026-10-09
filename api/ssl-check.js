// api/ssl-check.js
//
// Free SSL/TLS test tool for Codex Security (same idea as ssllabs.com, kept
// simple and self-hosted). Deploy this file in the project's /api folder on
// Vercel and it becomes GET /api/ssl-check?domain=example.com
//
// What it does:
//   1. Validates the domain the visitor typed in.
//   2. Resolves it and refuses to test private/internal/cloud-metadata
//      addresses (basic SSRF protection — important because this endpoint
//      makes an outbound connection to whatever the visitor types).
//   3. Opens a real TLS connection to the target on port 443 and reads back
//      the negotiated protocol, cipher and certificate.
//   4. Makes a lightweight HTTPS request to check for the HSTS header.
//   5. Scores all of that into a letter grade (A+ down to F), loosely
//      modelled on Qualys SSL Labs' public methodology, not identical to it.
//   6. Emails a short lead/report to your inbox (see notifyTeam below) so
//      your team knows a prospect just tested a domain.
//
// No npm dependencies — everything here is a Node.js built-in module, plus
// the global fetch() that's available in Vercel's Node 18+ runtime.
//
// Required environment variables (set in Vercel → Project → Settings →
// Environment Variables):
//   RESEND_API_KEY   API key from https://resend.com (free tier is plenty
//                    for this volume). Without it, the tool still works —
//                    it just logs the lead instead of emailing it.
//   NOTIFY_EMAIL     Where reports are sent. Defaults to
//                    contact@codexsecurity.co if not set.
//   FROM_EMAIL       The verified sender address Resend will send from,
//                    e.g. "Codex Security Tools <tools@codexsecurity.co>".
//                    Requires verifying codexsecurity.co in Resend first.

const tls = require("tls");
const https = require("https");
const dns = require("dns").promises;
const net = require("net");

const TIMEOUT_MS = 8000;

// ---------- input validation & SSRF protection ----------

function cleanDomain(raw) {
  if (!raw || typeof raw !== "string") return null;
  let d = raw.trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "");
  d = d.split("/")[0];
  d = d.split(":")[0];
  d = d.split("?")[0];
  // basic hostname shape check
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) {
    return null;
  }
  if (d.length > 253) return null;
  return d;
}

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return true;
  if (p[0] === 10) return true; // RFC1918
  if (p[0] === 127) return true; // loopback
  if (p[0] === 0) return true;
  if (p[0] === 169 && p[1] === 254) return true; // link-local + cloud metadata (169.254.169.254)
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true; // RFC1918
  if (p[0] === 192 && p[1] === 168) return true; // RFC1918
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  return false;
}

function isPrivateIPv6(ip) {
  const l = ip.toLowerCase();
  if (l === "::1") return true; // loopback
  if (l.startsWith("fe80:")) return true; // link-local
  if (l.startsWith("fc") || l.startsWith("fd")) return true; // unique local
  if (l.startsWith("::ffff:")) return isPrivateIPv4(l.replace("::ffff:", ""));
  return false;
}

async function resolveSafely(hostname) {
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new Error("Could not resolve that domain. Check the spelling and try again.");
  }
  if (!addresses.length) throw new Error("Could not resolve that domain.");

  for (const a of addresses) {
    const bad = net.isIPv6(a.address) ? isPrivateIPv6(a.address) : isPrivateIPv4(a.address);
    if (bad) {
      throw new Error("That domain resolves to a private or internal address and can't be tested here.");
    }
  }
  return addresses[0].address;
}

// ---------- TLS probe ----------

function probeTLS(hostname, ip) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: ip,
        port: 443,
        servername: hostname, // SNI — must stay the hostname, not the IP
        rejectUnauthorized: false, // we want to inspect bad certs too, not just abort
        timeout: TIMEOUT_MS,
      },
      () => {
        const cert = socket.getPeerCertificate(false);
        const result = {
          protocol: socket.getProtocol(), // e.g. "TLSv1.3"
          cipher: socket.getCipher(), // { name, version }
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          cert: cert && cert.subject
            ? {
                subject: cert.subject.CN || null,
                issuer: cert.issuer ? cert.issuer.O || cert.issuer.CN : null,
                validFrom: cert.valid_from || null,
                validTo: cert.valid_to || null,
              }
            : null,
        };
        socket.end();
        resolve(result);
      }
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection to the server timed out on port 443."));
    });
    socket.on("error", (err) => reject(new Error("Could not open a TLS connection: " + err.message)));
  });
}

function probeHSTS(hostname, ip) {
  return new Promise((resolve) => {
    const req = https.request(
      {
        host: ip,
        servername: hostname,
        headers: { Host: hostname, "User-Agent": "CodexSecurity-SSLTest/1.0" },
        port: 443,
        path: "/",
        method: "HEAD",
        rejectUnauthorized: false,
        timeout: TIMEOUT_MS,
      },
      (res) => {
        resolve({
          hsts: res.headers["strict-transport-security"] || null,
          xfo: res.headers["x-frame-options"] || null,
          xcto: res.headers["x-content-type-options"] || null,
        });
        res.resume();
      }
    );
    req.on("timeout", () => {
      req.destroy();
      resolve({ hsts: null, xfo: null, xcto: null });
    });
    req.on("error", () => resolve({ hsts: null, xfo: null, xcto: null }));
    req.end();
  });
}

// ---------- grading ----------

function gradeProtocol(protocol) {
  switch (protocol) {
    case "TLSv1.3":
      return { score: 100, label: "TLS 1.3", status: "good" };
    case "TLSv1.2":
      return { score: 85, label: "TLS 1.2", status: "good" };
    case "TLSv1.1":
      return { score: 45, label: "TLS 1.1 (outdated)", status: "warn" };
    case "TLSv1":
      return { score: 30, label: "TLS 1.0 (outdated)", status: "warn" };
    default:
      return { score: 0, label: (protocol || "Unknown") + " (insecure or undetected)", status: "fail" };
  }
}

function gradeCipher(cipher) {
  const name = (cipher && cipher.name) || "";
  if (/GCM|CHACHA20|POLY1305|AES.*GCM/i.test(name)) {
    return { score: 100, label: name + " (strong, authenticated)", status: "good" };
  }
  if (/CBC/i.test(name)) {
    return { score: 55, label: name + " (older, CBC mode)", status: "warn" };
  }
  if (/RC4|DES|EXPORT|NULL/i.test(name) || !name) {
    return { score: 0, label: (name || "No cipher negotiated") + " (weak)", status: "fail" };
  }
  return { score: 70, label: name, status: "warn" };
}

function gradeCertificate({ authorized, authorizationError, cert }) {
  if (!cert || !cert.validTo) {
    return { score: 0, label: "No certificate returned", status: "fail", expired: true };
  }
  const now = Date.now();
  const validTo = new Date(cert.validTo).getTime();
  const daysLeft = Math.round((validTo - now) / 86400000);

  if (Number.isNaN(validTo) || daysLeft < 0) {
    return { score: 0, label: "Certificate has expired", status: "fail", expired: true, daysLeft };
  }
  if (!authorized) {
    return {
      score: 20,
      label: "Certificate is not trusted (" + (authorizationError || "verification failed") + ")",
      status: "fail",
      daysLeft,
      untrusted: true,
    };
  }
  if (daysLeft < 15) {
    return { score: 55, label: `Valid, but expires in ${daysLeft} day(s)`, status: "warn", daysLeft };
  }
  if (daysLeft < 30) {
    return { score: 80, label: `Valid, expires in ${daysLeft} days`, status: "warn", daysLeft };
  }
  return { score: 100, label: `Valid, expires in ${daysLeft} days`, status: "good", daysLeft };
}

function gradeHSTS(hstsHeader) {
  if (!hstsHeader) return { score: 0, label: "Not set", status: "warn", bonus: 0 };
  const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  if (maxAge >= 15552000) return { score: 100, label: "Enabled, long max-age", status: "good", bonus: 5 }; // 180 days+
  if (maxAge > 0) return { score: 60, label: "Enabled, short max-age", status: "warn", bonus: 2 };
  return { score: 30, label: "Header present but malformed", status: "warn", bonus: 0 };
}

function letterGrade(score, caps) {
  let grade;
  if (score >= 97) grade = "A+";
  else if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 65) grade = "C";
  else if (score >= 45) grade = "D";
  else grade = "F";

  // Caps, same spirit as SSL Labs: a broken trust chain or expired cert
  // can't earn a good grade no matter how modern the protocol is.
  const order = ["F", "D", "C", "B", "A", "A+"];
  for (const cap of caps) {
    if (order.indexOf(grade) > order.indexOf(cap)) grade = cap;
  }
  return grade;
}

function computeGrade({ protocolG, cipherG, certG, hstsG }) {
  const weighted =
    protocolG.score * 0.3 + cipherG.score * 0.3 + certG.score * 0.3 + hstsG.score * 0.1;
  const caps = [];
  if (certG.expired) caps.push("F");
  else if (certG.untrusted) caps.push("C");
  if (protocolG.status === "fail") caps.push("D");
  if (cipherG.status === "fail") caps.push("D");

  const grade = letterGrade(weighted, caps.length ? caps : ["A+"]);
  return { score: Math.round(weighted), grade };
}

// ---------- notify the team ----------

async function notifyTeam({ domain, grade, score, ip, visitorIp, checks }) {
  const toAddr = process.env.NOTIFY_EMAIL || "contact@codexsecurity.co";
  const fromAddr = process.env.FROM_EMAIL || "Codex Security Tools <onboarding@resend.dev>";

  const summary = `
    <h2 style="margin:0 0 12px">Free SSL test run</h2>
    <p><strong>Domain:</strong> ${domain}</p>
    <p><strong>Grade:</strong> ${grade} (${score}/100)</p>
    <p><strong>Resolved IP:</strong> ${ip}</p>
    <p><strong>Visitor IP:</strong> ${visitorIp || "unknown"}</p>
    <p><strong>Time:</strong> ${new Date().toISOString()}</p>
    <hr>
    <p><strong>Protocol:</strong> ${checks.protocolG.label}</p>
    <p><strong>Cipher:</strong> ${checks.cipherG.label}</p>
    <p><strong>Certificate:</strong> ${checks.certG.label}</p>
    <p><strong>HSTS:</strong> ${checks.hstsG.label}</p>
    <hr>
    <p style="color:#666;font-size:13px">This lead came from the free SSL test tool on your website. Consider following up, especially if the grade is C or below.</p>
  `;

  if (!process.env.RESEND_API_KEY) {
    console.log("[ssl-check] RESEND_API_KEY not set — logging lead instead of emailing it:");
    console.log({ domain, grade, score, ip, visitorIp });
    return { sent: false, reason: "no_api_key" };
  }

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: fromAddr,
        to: [toAddr],
        subject: `SSL test: ${domain} — Grade ${grade}`,
        html: summary,
      }),
    });
    if (!res.ok) {
      console.error("[ssl-check] Resend API error:", res.status, await res.text());
      return { sent: false, reason: "api_error" };
    }
    return { sent: true };
  } catch (err) {
    console.error("[ssl-check] Failed to send notification email:", err);
    return { sent: false, reason: "network_error" };
  }
}

// ---------- in-memory rate limit (per serverless instance — good enough to
// slow down casual abuse; use Upstash/Redis for a hard limit in production) ----------

const hits = new Map();
function rateLimited(key, max = 8, windowMs = 60000) {
  const now = Date.now();
  const entry = hits.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + windowMs;
  }
  entry.count += 1;
  hits.set(key, entry);
  return entry.count > max;
}

// ---------- handler ----------

module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  const visitorIp =
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket?.remoteAddress || "unknown";

  if (rateLimited(visitorIp)) {
    res.statusCode = 429;
    return res.end(JSON.stringify({ error: "Too many tests from this address. Please wait a minute and try again." }));
  }

  const domain = cleanDomain(req.query ? req.query.domain : new URL(req.url, "http://x").searchParams.get("domain"));
  if (!domain) {
    res.statusCode = 400;
    return res.end(JSON.stringify({ error: "Enter a valid domain, e.g. example.com" }));
  }

  try {
    const ip = await resolveSafely(domain);
    const [tlsResult, hstsResult] = await Promise.all([probeTLS(domain, ip), probeHSTS(domain, ip)]);

    const protocolG = gradeProtocol(tlsResult.protocol);
    const cipherG = gradeCipher(tlsResult.cipher);
    const certG = gradeCertificate(tlsResult);
    const hstsG = gradeHSTS(hstsResult.hsts);

    const { grade, score } = computeGrade({ protocolG, cipherG, certG, hstsG });

    // Fire-and-forget: don't make the visitor wait on the email send.
    notifyTeam({ domain, grade, score, ip, visitorIp, checks: { protocolG, cipherG, certG, hstsG } }).catch(() => {});

    res.statusCode = 200;
    return res.end(
      JSON.stringify({
        domain,
        ip,
        grade,
        score,
        checks: {
          protocol: protocolG,
          cipher: cipherG,
          certificate: certG,
          hsts: hstsG,
        },
        testedAt: new Date().toISOString(),
      })
    );
  } catch (err) {
    res.statusCode = 200; // still 200 so the frontend can render a friendly message
    return res.end(JSON.stringify({ error: err.message || "The test could not be completed." }));
  }
};
