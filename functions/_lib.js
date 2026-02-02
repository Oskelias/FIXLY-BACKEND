// ==== SHARED HELPERS FOR CLOUDFLARE PAGES FUNCTIONS ====

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  });
}

export function nowISO() {
  return new Date().toISOString();
}

// ==== JWT HELPERS ====
function b64urlFromUint8(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlEncodeJSON(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  return b64urlFromUint8(bytes);
}

function b64urlToUint8(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "==".slice((2 - b64url.length * 3 % 4) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export async function generateJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64urlEncodeJSON(header);
  const encPayload = b64urlEncodeJSON(payload);
  const data = `${encHeader}.${encPayload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
  return `${data}.${b64urlFromUint8(sig)}`;
}

export async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const [encHeader, encPayload, encSig] = parts;
  const data = `${encHeader}.${encPayload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify("HMAC", key, b64urlToUint8(encSig), new TextEncoder().encode(data));
  if (!ok) throw new Error("Invalid JWT signature");
  const payload = JSON.parse(new TextDecoder().decode(b64urlToUint8(encPayload)));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error("JWT has expired");
  return payload;
}

// ==== PASSWORD HELPERS ====
export async function sha256Hex(input) {
  const enc = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function hashPassword(password) {
  return sha256Hex(password);
}

export async function verifyPassword(password, hash) {
  return (await hashPassword(password)) === hash;
}

// ==== AUTH HELPERS ====
export async function authenticateRequest(request, env, requireAdmin = false) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    throw new Error("No authorization token provided");
  }
  const token = auth.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);

  // Verify session exists in DB
  const session = await env.DB.prepare(`
    SELECT id, device_id, user_id, tenant_id, created_at
    FROM user_sessions
    WHERE user_id = ? AND tenant_id = ? AND device_id = ?
  `).bind(payload.userId, payload.tenantId, payload.deviceId).first();

  if (!session) {
    throw new Error("Session has been revoked or does not exist");
  }

  if (requireAdmin && payload.role !== "admin") {
    throw new Error("Admin access required");
  }

  return payload;
}

export function getLocationId(request, data = {}) {
  const url = new URL(request.url);
  return (
    request.headers.get("X-Location-Id") ||
    url.searchParams.get("locationId") ||
    url.searchParams.get("location_id") ||
    data.locationId ||
    data.location_id ||
    ""
  );
}

export async function manageDeviceSessions(user, env, token, deviceId, meta = {}) {
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const sessions = await env.DB.prepare(
    `SELECT id, device_id, created_at FROM user_sessions
     WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC`
  ).bind(user.id, user.tenant_id).all();

  if ((sessions.results?.length || 0) >= 3) {
    const oldest = sessions.results[sessions.results.length - 1];
    await env.DB.prepare(`DELETE FROM user_sessions WHERE id = ?`).bind(oldest.id).run();
  }

  await env.DB.prepare(`
    INSERT OR REPLACE INTO user_sessions
      (user_id, tenant_id, device_id, token_hash, expires_at, device_name, ip_address, user_agent, last_activity, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `).bind(
    user.id,
    user.tenant_id,
    deviceId,
    tokenHash,
    expiresAt,
    meta.deviceName || "",
    meta.ip || "",
    meta.ua || ""
  ).run();
}

export async function generateOrderNumber(tenantId, locationId, db) {
  const r = await db.prepare(`
    SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ? AND location_id = ?
  `).bind(tenantId, locationId).first();
  const next = (r?.count || 0) + 1;
  return `ORD-${String(next).padStart(4, "0")}`;
}
