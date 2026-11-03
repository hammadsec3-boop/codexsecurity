// api/tool-log.js — emails the team a short note whenever a free tool on /tools.html is used.
// Uses the same env vars as the other endpoints: RESEND_API_KEY, NOTIFY_EMAIL, FROM_EMAIL.
// PRIVACY: the browser sends only the tool name, the domain (email checker) and a result summary.
// Passwords and JWTs are NEVER sent to this endpoint.
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const TOOLS = { password: "Password checker", jwt: "JWT decoder" };
const hits = new Map();
function limited(k) { const n = Date.now(), e = hits.get(k) || { c: 0, r: n + 60000 }; if (n > e.r) { e.c = 0; e.r = n + 60000; } e.c++; hits.set(k, e); return e.c > 12; }

module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method === "GET") { // health check: open /api/tool-log in a browser
    return res.end(JSON.stringify({ deployed: true, resend_key_set: !!process.env.RESEND_API_KEY, to: process.env.NOTIFY_EMAIL || "contact@codexsecurity.co (default)", from: process.env.FROM_EMAIL || "onboarding@resend.dev (default - only works for your Resend signup email)" }));
  }
  if (req.method !== "POST") { res.statusCode = 405; return res.end("{}"); }
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (limited(ip)) { res.statusCode = 429; return res.end("{}"); }
  let b = req.body; if (typeof b === "string") { try { b = JSON.parse(b); } catch { b = {}; } } b = b || {};
  const tool = TOOLS[b.tool]; if (!tool) { res.statusCode = 400; return res.end("{}"); }
  const rows = Object.entries(b.data || {}).slice(0, 12).map(([k, v]) => `<p><strong>${esc(String(k).slice(0, 40))}:</strong> ${esc(String(v).slice(0, 300))}</p>`).join("");
  const key = process.env.RESEND_API_KEY; if (!key) return res.end(JSON.stringify({ ok: false }));
  const subject = `Free tool used: ${tool}${b.data && b.data.domain ? " - " + String(b.data.domain).slice(0, 80) : ""}`;
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: process.env.FROM_EMAIL || "Codex Security Tools <onboarding@resend.dev>",
        to: [process.env.NOTIFY_EMAIL || "contact@codexsecurity.co"],
        subject,
        html: `<h2>${esc(tool)}</h2>${rows}<hr><p><strong>Visitor IP:</strong> ${esc(ip)}</p><p><strong>Time:</strong> ${new Date().toISOString()}</p><p style="color:#666;font-size:12px">Sent from the free tools page. Passwords and tokens are never included.</p>`,
      }),
    });
    if (!r.ok) { const t = await r.text(); console.error("[tool-log] Resend", r.status, t); return res.end(JSON.stringify({ ok: false, resend_status: r.status, detail: t.slice(0, 300) })); }
  } catch (e) { console.error("[tool-log]", e); return res.end(JSON.stringify({ ok: false, error: String(e).slice(0, 200) })); }
  res.end(JSON.stringify({ ok: true }));
};
