// POST /api/waitlist  { email, role, note? }
//
// Stores a delegation-waitlist signup in the WAITLIST KV namespace (bound in
// the Pages project's settings). No third-party service sees the address.
// Without the binding the endpoint says so and the page falls back to email.

const ROLES = new Set(["owner", "developer", "agency", "other"]);
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

export async function onRequestPost({ request, env }) {
  if (!env.WAITLIST) {
    return json({ ok: false, error: "not_configured" }, 503);
  }
  let data;
  try {
    data = await request.json();
  } catch {
    return json({ ok: false, error: "bad_request" }, 400);
  }
  // The honeypot field is hidden from people; a bot that fills it is ignored politely.
  if (typeof data.website === "string" && data.website.length > 0) {
    return json({ ok: true });
  }
  const email = String(data.email || "").trim().toLowerCase();
  const role = String(data.role || "other").trim();
  const note = String(data.note || "").trim().slice(0, 500);
  if (!EMAIL.test(email) || email.length > 254) {
    return json({ ok: false, error: "invalid_email" }, 400);
  }
  if (!ROLES.has(role)) {
    return json({ ok: false, error: "invalid_role" }, 400);
  }
  // One signup per address every ten minutes, keyed by a hash so the raw
  // address is not used as a key name.
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email));
  const id = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const existing = await env.WAITLIST.get(`signup:${id}`);
  if (existing) {
    return json({ ok: true, already: true });
  }
  const record = {
    email,
    role,
    note,
    at: new Date().toISOString(),
    country: request.headers.get("cf-ipcountry") || "",
    ua: (request.headers.get("user-agent") || "").slice(0, 200),
  };
  await env.WAITLIST.put(`signup:${id}`, JSON.stringify(record));
  return json({ ok: true });
}

export async function onRequestGet() {
  return json({ ok: false, error: "method_not_allowed" }, 405);
}
