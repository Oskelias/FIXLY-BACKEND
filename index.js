// =========================
// FIXLY-BACKEND — index.js
// PASTE ESTO ENTERO (reemplazá TODO tu index.js por este)
// =========================

// ==== CORS (FIX) — normaliza dominios y SIEMPRE responde preflight ====
function __normOrigin(v) {
  try {
    if (!v) return "";
    // si te meten url con path, lo convertimos a origin
    return new URL(v).origin;
  } catch {
    return (v || "").trim().replace(/\/+$/, "");
  }
}

function __fix_allowedOrigins(env) {
  const set = new Set();

  const add = (x) => {
    const o = __normOrigin(x);
    if (o) set.add(o);
  };

  add(env?.ADMIN_DOMAIN);
  add(env?.APP_DOMAIN);

  if (env?.CORS_ALLOWED && typeof env.CORS_ALLOWED === "string") {
    env.CORS_ALLOWED.split(",").forEach((o) => add(o));
  }

  // opcional: permitir *.pages.dev si usás previews
  // (comentá si no lo querés)
  set.add("https://admin-fixly-taller.pages.dev");

  return set;
}

function __fix_withCORS(resp, request, env) {
  const origin = request.headers.get("Origin") || "";
  const allow = __fix_allowedOrigins(env);

  const h = new Headers(resp.headers);

  // CORS solo si el Origin está permitido
  if (origin && allow.has(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Vary", "Origin");
    h.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-Id, X-Device-Name");
    // h.set("Access-Control-Allow-Credentials", "true"); // solo si usás cookies
  }

  return new Response(resp.body, { status: resp.status, headers: h });
}

function __fix_handlePreflight(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allow = __fix_allowedOrigins(env);

  const reqHeaders = request.headers.get("Access-Control-Request-Headers") || "Content-Type, Authorization, X-Tenant-Id, X-Device-Name";

  const headers = {
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    "Access-Control-Allow-Headers": reqHeaders,
    "Access-Control-Max-Age": "86400",
  };

  if (origin && allow.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
    // headers["Access-Control-Allow-Credentials"] = "true";
  }

  return new Response(null, { status: 204, headers });
}
// ==== /CORS (FIX) ====


// ==== MP WEBHOOK HELPERS (safe, idempotent) ====
async function __mp_verifyHmac(raw, secret, signatureHeader) {
  try {
    const v1 = /v1=([^,]+)/.exec(signatureHeader || "")?.[1] || (signatureHeader || "");
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret || ""),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(raw || ""));
    const digest = btoa(String.fromCharCode(...new Uint8Array(sig)));
    return __mp_timingSafeEqual(digest, v1);
  } catch (e) {
    return false;
  }
}
function __mp_timingSafeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let res = 0;
  for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}
async function __mp_upsertPaymentInDB(payment, env) {
  try {
    if (!env || !env.DB) return;
    const id = payment?.id?.toString?.() || "";
    const status = payment?.status || "";
    const email = payment?.payer?.email || "";
    if (!id) return;

    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS pagos (id TEXT PRIMARY KEY, status TEXT, email TEXT, created_at TEXT)"
    ).run();

    await env.DB.prepare(
      "INSERT INTO pagos (id, status, email, created_at) VALUES (?1, ?2, ?3, datetime('now')) ON CONFLICT(id) DO UPDATE SET status=excluded.status, email=excluded.email"
    )
      .bind(id, status, email)
      .run();
  } catch (e) {
    // swallow
  }
}
// ==== /MP WEBHOOK HELPERS ====


// ==== helpers base ====
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function nowISO() {
  return new Date().toISOString();
}

async function sha256Hex(input) {
  const enc = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

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
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "==".slice((2 - (b64url.length * 3) % 4) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function generateJWT(payload, secret) {
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
  const encSig = b64urlFromUint8(sig);
  return `${data}.${encSig}`;
}

async function verifyJWT(token, secret) {
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
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1e3)) throw new Error("JWT has expired");
  return payload;
}

async function hashPassword(password) {
  return sha256Hex(password);
}

async function verifyPassword(password, hash) {
  if (typeof hash !== "string") return false;
  const normalized = hash.trim();
  const computed = await hashPassword(password);

  if (computed === normalized) return true;
  if (/^[a-fA-F0-9]{64}$/.test(normalized) && computed === normalized.toLowerCase()) return true;

  return false;
}

async function authenticateRequest(request, env, requireAdmin = false) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) throw new Error("No authorization token provided");

  const token = auth.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);

  const session = await env.DB.prepare(`
    SELECT id, device_id, user_id, tenant_id, created_at 
    FROM user_sessions 
    WHERE user_id = ? AND tenant_id = ? AND device_id = ?
  `)
    .bind(payload.userId, payload.tenantId, payload.deviceId)
    .first();

  if (!session) throw new Error("Session has been revoked or does not exist");
  if (requireAdmin && payload.role !== "admin") throw new Error("Admin access required");

  return payload;
}

async function manageDeviceSessions(user, env, token, deviceId, meta = {}) {
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1e3).toISOString();

  const sessions = await env.DB.prepare(
    `SELECT id, device_id, created_at FROM user_sessions 
     WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC`
  )
    .bind(user.id, user.tenant_id)
    .all();

  if ((sessions.results?.length || 0) >= 3) {
    const oldest = sessions.results[sessions.results.length - 1];
    await env.DB.prepare(`DELETE FROM user_sessions WHERE id = ?`).bind(oldest.id).run();
  }

  await env.DB.prepare(`
    INSERT OR REPLACE INTO user_sessions
      (user_id, tenant_id, device_id, token_hash, expires_at, device_name, ip_address, user_agent, last_activity, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `)
    .bind(
      user.id,
      user.tenant_id,
      deviceId,
      tokenHash,
      expiresAt,
      meta.deviceName || "",
      meta.ip || "",
      meta.ua || ""
    )
    .run();
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) return json({ success: false, error: "Username and password are required" }, 400);

  const user = await env.DB.prepare(`SELECT * FROM users WHERE username = ? AND status != ?`)
    .bind(username, "deleted")
    .first();

  if (!user) return json({ success: false, error: "Invalid credentials" }, 401);

  let ok = await verifyPassword(password, user.password);

  // Legacy compatibility: if an old record still stores plaintext,
  // allow one successful login and migrate it to SHA-256 immediately.
  if (!ok && typeof user.password === "string" && user.password === password) {
    const migratedHash = await hashPassword(password);
    await env.DB.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(migratedHash, user.id).run();
    ok = true;
  }

  if (!ok) return json({ success: false, error: "Invalid credentials" }, 401);

  if (user.status === "paused") return json({ success: false, error: "Account is paused" }, 403);

  if (user.status === "trial" && user.trial_ends_at) {
    if (new Date(user.trial_ends_at) < new Date()) {
      await env.DB.prepare(`UPDATE users SET status = ? WHERE id = ?`).bind("expired", user.id).run();
      return json({ success: false, error: "Trial period has expired" }, 403);
    }
  }

  const deviceId = crypto.randomUUID();
  const payload = {
    userId: user.id,
    username: user.username,
    tenantId: user.tenant_id,
    role: user.role,
    plan: user.plan,
    deviceId,
    exp: Math.floor(Date.now() / 1e3) + 24 * 60 * 60,
  };

  const token = await generateJWT(payload, env.JWT_SECRET);

  await manageDeviceSessions(user, env, token, deviceId, {
    deviceName: request.headers.get("X-Device-Name") || "",
    ip: request.headers.get("CF-Connecting-IP") || "",
    ua: request.headers.get("User-Agent") || "",
  });

  await env.DB.prepare(`UPDATE users SET last_login = datetime(?) WHERE id = ?`).bind(nowISO(), user.id).run();

  return json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username || "",
      tenantId: user.tenant_id || "",
      role: user.role || "",
      plan: user.plan || "",
      status: user.status || "",
      redirectUrl: user.role === "admin" ? "/admin" : "/app",
    },
  });
}

async function handleLogout(request, env) {
  try {
    const payload = await authenticateRequest(request, env);
    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE user_id = ? AND tenant_id = ? AND device_id = ?`
    )
      .bind(payload.userId, payload.tenantId, payload.deviceId)
      .run();
    return json({ success: true });
  } catch {
    return json({ success: true });
  }
}

// ====== Admin/App routes: dejá tus implementaciones actuales si ya las tenías ======
// Si tu archivo original ya tenía handleAdminRoutes/handleAppRoutes completos,
// podés pegarlos acá tal cual. Yo dejo placeholders simples para no romper build.

async function handleAdminRoutes(request, env, path, method) {
  try {
    await authenticateRequest(request, env, true);
  } catch (err) {
    const msg = err?.message || "";
    if (msg.includes("Admin") || msg.includes("permission")) return json({ error: "Forbidden" }, 403);
    return json({ error: "Unauthorized" }, 401);
  }
  // TODO: pegá acá tu handleAdminRoutes completo si lo tenías
  return json({ error: "Admin endpoint not found" }, 404);
}

async function handleAppRoutes(request, env, path, method) {
  try {
    await authenticateRequest(request, env);
  } catch {
    return json({ error: "Unauthorized" }, 401);
  }
  // TODO: pegá acá tu handleAppRoutes completo si lo tenías
  return json({ error: "App endpoint not found" }, 404);
}

// ====== Health ======
function healthPayload() {
  return {
    ok: true,
    version: "2.0.0-corsfix",
    timestamp: nowISO(),
    endpoints: ["GET /health", "POST /api/auth/login", "POST /api/auth/logout"],
  };
}

// ====== MP webhook ======
async function handleMPWebhook(request, env) {
  const signature = request.headers.get("x-signature");
  const requestId = request.headers.get("x-request-id");
  if (!signature || !requestId) return json({ ok: false, error: "missing headers" }, 400);

  const raw = await request.text();
  const ok = await __mp_verifyHmac(raw, env.MP_WEBHOOK_SECRET, signature);
  if (!ok) return json({ ok: false, error: "invalid signature" }, 401);

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return json({ ok: false, error: "bad json" }, 400);
  }

  const type = payload?.type;
  const id = payload?.data?.id;

  if (type === "payment" && id) {
    const r = await fetch(`https://api.mercadopago.com/v1/payments/${id}`, {
      headers: { Authorization: `Bearer ${env.MP_ACCESS_TOKEN}` },
    });
    if (!r.ok) return json({ ok: false, error: "mp fetch error" }, 502);
    const payment = await r.json();
    await __mp_upsertPaymentInDB(payment, env);
    return json({ ok: true });
  }

  return json({ ok: true, ignored: true });
}

// ====== Worker fetch ======
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const rawPath = decodeURIComponent(url.pathname);
    const path = rawPath.trim().replace(/\/+$/, "");
    const method = request.method;

    // ✅ PRE-FLIGHT CORS (esto te estaba rompiendo el navegador)
    if (method === "OPTIONS") {
      return __fix_handlePreflight(request, env);
    }

    // Webhook MercadoPago
    if (path === "/webhooks/mercadopago" && method === "POST") {
      return handleMPWebhook(request, env); // server-to-server, no CORS necesario
    }

    // Health
    if (path === "/health" && method === "GET") {
      return __fix_withCORS(json(healthPayload(), 200), request, env);
    }

    // Auth (✅ acá tu front puede pegarle desde admin.fixlytaller.com)
    if (path === "/api/auth/login" && method === "POST") {
      return __fix_withCORS(await handleLogin(request, env), request, env);
    }
    // alias por si algún front viejo pega a /auth/login
    if (path === "/auth/login" && method === "POST") {
      return __fix_withCORS(await handleLogin(request, env), request, env);
    }

    if (path === "/api/auth/logout" && method === "POST") {
      return __fix_withCORS(await handleLogout(request, env), request, env);
    }

    // Rutas admin/app (si las usás)
    if (path.startsWith("/api/admin/")) {
      return __fix_withCORS(await handleAdminRoutes(request, env, path, method), request, env);
    }
    if (path.startsWith("/api/app/") || path.startsWith("/api/devices")) {
      return __fix_withCORS(await handleAppRoutes(request, env, path, method), request, env);
    }

    return __fix_withCORS(json({ error: "Endpoint no encontrado", path, method }, 404), request, env);
  },
};
