// api/contact.js — receives the website contact form and emails it to the team via Resend.
// Env vars (Vercel → Settings → Environment Variables): RESEND_API_KEY (required),
// NOTIFY_EMAIL (where to receive; until codexsecurity.co is verified in Resend use your Resend signup email),
// FROM_EMAIL (optional, e.g. "Codex Security <contact@codexsecurity.co>" after domain verification).
const esc = (s) => String(s || "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hits = new Map();
function limited(k) { const n = Date.now(), e = hits.get(k) || { c: 0, r: n + 60000 }; if (n > e.r) { e.c = 0; e.r = n + 60000; } e.c++; hits.set(k, e); return e.c > 5; }

module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method !== "POST") { res.statusCode = 405; return res.end(JSON.stringify({ error: "POST only" })); }
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (limited(ip)) { res.statusCode = 429; return res.end(JSON.stringify({ error: "Too many messages. Please wait a minute." })); }

  let b = req.body;
  if (typeof b === "string") { try { b = JSON.parse(b); } catch { b = {}; } }
  b = b || {};
  if (b.website) return res.end(JSON.stringify({ ok: true })); // honeypot
  const name = String(b.name || "").trim().slice(0, 120);
  const email = String(b.email || "").trim().slice(0, 200);
  const service = String(b.service || "").trim().slice(0, 120);
  const message = String(b.message || "").trim().slice(0, 5000);
  if (!name || !message || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.statusCode = 400; return res.end(JSON.stringify({ error: "Please fill in your name, a valid email and a message." }));
  }
  const key = process.env.RESEND_API_KEY;
  if (!key) { console.error("[contact] RESEND_API_KEY missing"); res.statusCode = 500; return res.end(JSON.stringify({ error: "Mail service not configured." })); }

  const html = `<h2>New website enquiry</h2><p><strong>Name:</strong> ${esc(name)}</p><p><strong>Email:</strong> ${esc(email)}</p><p><strong>Service:</strong> ${esc(service)}</p><p><strong>Message:</strong></p><p>${esc(message).replace(/\n/g, "<br>")}</p><hr><p style="color:#666;font-size:12px">IP ${esc(ip)} · ${new Date().toISOString()}</p>`;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.FROM_EMAIL || "Codex Security Website <onboarding@resend.dev>",
        to: [process.env.NOTIFY_EMAIL || "contact@codexsecurity.co"],
        reply_to: email,
        subject: `Website enquiry: ${service || "General"} — ${name}`,
        html,
      }),
    });
    if (!r.ok) { console.error("[contact] Resend", r.status, await r.text()); res.statusCode = 502; return res.end(JSON.stringify({ error: "Could not send right now." })); }
    return res.end(JSON.stringify({ ok: true }));
  } catch (e) { console.error("[contact]", e); res.statusCode = 502; return res.end(JSON.stringify({ error: "Could not send right now." })); }
};
