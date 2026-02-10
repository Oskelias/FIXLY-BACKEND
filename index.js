// =========================
// FIXLY-BACKEND — index.js
// REEMPLAZÁ TODO TU ARCHIVO POR ESTE
// =========================

// ---------- CORS helpers ----------
function __normOrigin(v) {
  try {
    if (!v) return "";
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

  // previews / pages dev (si querés, dejalo; si no, borralo)
  add("https://admin-fixly-taller.pages.dev");

  return set;
}

function __fix_withCORS(resp, request, env) {
  const origin = request.headers.get("Origin") || "";
  const allow = __fix_allowedOrigins(env);
  const h = new Headers(resp.headers);

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

  const reqHeaders =
    request.headers.get("Access-Control-Request-Headers") ||
    "Content-Type, Authorization, X-Tenant-Id, X-Device-Name";

  const headers = {
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    "Access-Control-Allow-Headers": reqHeaders,
    "Access-Control-Max-Age": "86400",
  };

  if (origin && allow.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return new Response(null, { status: 204, headers });
}

// ---------- base helpers ----------
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
  const enc = new TextEncoder().encode(String(input ?? ""));
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
  if (!secret) throw new Error("JWT_SECRET not configured");
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
  if (!secret) throw new Error("JWT_SECRET not configured");
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

async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;
  const normalized = stored.trim();
  const computed = await hashPassword(password);

  if (computed === normalized) return true;
  if (/^[a-fA-F0-9]{64}$/.test(normalized) && computed === normalized.toLowerCase()) return true;

  return false;
}

// ---------- auth/session ----------
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

// ---------- endpoints ----------
async function handleLogin(request, env) {
  const { username, password } = await request.json().catch(() => ({}));
  if (!username || !password) return json({ success: false, error: "Username and password are required" }, 400);

  const user = await env.DB.prepare(`SELECT * FROM users WHERE username = ? AND status != ?`)
    .bind(username, "deleted")
    .first();

  if (!user) return json({ success: false, error: "Invalid credentials" }, 401);

  let ok = await verifyPassword(password, user.password);

  // compat legacy: si quedó plaintext, migramos a sha256 en el primer login válido
  if (!ok && typeof user.password === "string" && user.password === password) {
    const migratedHash = await hashPassword(password);
    await env.DB.prepare(`UPDATE users SET password = ? WHERE id = ?`).bind(migratedHash, user.id).run();
    ok = true;
  }

  if (!ok) return json({ success: false, error: "Invalid credentials" }, 401);
  if (user.status === "paused") return json({ success: false, error: "Account is paused" }, 403);

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

// Registro (flexible) para /auth/public/register
function __usernameFromEmail(email) {
  const base = (email.split("@")[0] || "user").replace(/[^a-z0-9._-]/gi, "").toLowerCase() || "user";
  return `${base}-${Math.random().toString(36).slice(2, 7)}`;
}

async function handlePublicRegister(request, env) {
  const body = await request.json().catch(() => ({}));

  const email = String(body.email || body.mail || "").trim();
  const password = String(body.password || body.pass || body.clave || "").trim();

  // campos opcionales
  const nombre = String(body.nombre || body.name || "").trim();
  const empresa = String(body.empresa || body.taller || body.company || "").trim();
  const telefono = String(body.telefono || body.phone || "").trim();

  if (!email || !password) {
    return json({ success: false, error: "email y password requeridos" }, 400);
  }

  // email duplicado
  const dup = await env.DB.prepare(`SELECT id FROM users WHERE email = ? AND status != ?`)
    .bind(email, "deleted")
    .first();
  if (dup) return json({ success: false, error: "El email ya está en uso" }, 409);

  // username único
  let username = __usernameFromEmail(email);
  for (let i = 0; i < 10; i++) {
    const ex = await env.DB.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
    if (!ex) break;
    username = __usernameFromEmail(email);
  }

  const hashed = await hashPassword(password);
  const tenantId = crypto.randomUUID();
  const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const res = await env.DB.prepare(`
    INSERT INTO users (username, password, email, tenant_id, role, plan, status, trial_ends_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
  `)
    .bind(username, hashed, email, tenantId, "user", "basic", "trial", trialEndsAt)
    .run();

  // Si querés guardar nombre/empresa/teléfono, usá una tabla perfil o agregá columnas.
  // Por ahora lo devolvemos en la respuesta para que el front lo use.

  return json({
    success: true,
    userId: res.meta?.last_row_id ?? null,
    user: { username, email, tenantId, nombre, empresa, telefono, trialEndsAt },
  }, 201);
}

// Forgot password (simple)
async function handleForgotPassword(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = String(body.email || body.mail || "").trim();
  if (!email) return json({ success: false, error: "email requerido" }, 400);

  // No revelamos si existe o no: siempre OK
  return json({ success: true, message: "Si el email existe, te enviamos instrucciones." }, 200);
}

// ---------- admin routes ----------
async function handleAdminRoutes(request, env, path, method) {
  try {
    await authenticateRequest(request, env, true);
  } catch (err) {
    const msg = err?.message || "";
    if (msg.includes("Admin") || msg.includes("permission")) return json({ error: "Forbidden" }, 403);
    return json({ error: "Unauthorized" }, 401);
  }

  // USERS
  if (path === "/api/admin/users" && method === "GET") {
    const users = await env.DB.prepare(`
      SELECT id, username, email, role, plan, status, trial_ends_at, created_at, updated_at, last_login, tenant_id
      FROM users WHERE status != ? ORDER BY created_at DESC
    `).bind("deleted").all();

    return json({ success: true, users: users.results }, 200);
  }

  if (path === "/api/admin/users" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const username = String(body.username || "").trim();
    const password = String(body.password || "").trim();
    const email = String(body.email || "").trim();
    const role = String(body.role || "user").trim() || "user";
    const plan = String(body.plan || "basic").trim() || "basic";
    const status = String(body.status || "trial").trim() || "trial";

    if (!username || !password) return json({ success: false, error: "Username and password are required" }, 400);

    const exists = await env.DB.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
    if (exists) return json({ success: false, error: "Username already exists" }, 409);

    const hashed = await hashPassword(password);
    const tenantId = crypto.randomUUID();
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    const res = await env.DB.prepare(`
      INSERT INTO users (username, password, email, tenant_id, role, plan, status, trial_ends_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    `).bind(username, hashed, email, tenantId, role, plan, status, trialEndsAt).run();

    return json({ success: true, userId: res.meta.last_row_id, tenantId }, 201);
  }

  if (/^\/api\/admin\/user\/([^\/]+)$/.test(path) && method === "PUT") {
    const username = path.split("/").pop();
    const updates = await request.json().catch(() => ({}));

    const fields = [];
    const vals = [];

    for (const k of ["email", "plan", "status", "role"]) {
      if (updates[k] !== undefined) {
        fields.push(`${k} = ?`);
        vals.push(updates[k]);
      }
    }

    if (updates.password) {
      const hashed = await hashPassword(String(updates.password));
      fields.push(`password = ?`);
      vals.push(hashed);
    }

    if (updates.extend_trial_days) {
      const u = await env.DB.prepare(`SELECT trial_ends_at FROM users WHERE username = ?`).bind(username).first();
      const cur = u?.trial_ends_at ? new Date(u.trial_ends_at) : new Date();
      const next = new Date(cur.getTime() + Number(updates.extend_trial_days) * 864e5);
      fields.push("trial_ends_at = ?");
      vals.push(next.toISOString());
    }

    if (!fields.length) return json({ success: false, error: "No valid fields to update" }, 400);

    fields.push(`updated_at = datetime('now')`);
    vals.push(username);

    await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE username = ? AND status != 'deleted'`)
      .bind(...vals)
      .run();

    return json({ success: true }, 200);
  }

  if (/^\/api\/admin\/user\/([^\/]+)$/.test(path) && method === "DELETE") {
    const username = path.split("/").pop();
    await env.DB.prepare(`UPDATE users SET status = ?, updated_at = datetime('now') WHERE username = ?`)
      .bind("deleted", username)
      .run();
    return json({ success: true }, 200);
  }

  if (/^\/api\/admin\/user\/([^\/]+)\/pause$/.test(path) && method === "PUT") {
    const username = path.split("/")[4];
    const body = await request.json().catch(() => ({}));
    const action = String(body.action || "").toLowerCase();
    const newStatus = action === "pause" ? "paused" : "active";
    await env.DB.prepare(`UPDATE users SET status = ?, updated_at = datetime('now') WHERE username = ?`)
      .bind(newStatus, username)
      .run();
    return json({ success: true }, 200);
  }

  // ✅ STATS (evita tu 404 del dashboard)
  // devolvemos algo simple y estable (podés sumar métricas reales después)
  if (
    (path === "/api/admin/stats" ||
      path === "/api/admin/dashboard/stats" ||
      path === "/api/stats" ||
      path === "/stats") &&
    method === "GET"
  ) {
    // métricas básicas desde DB si existen tablas (no rompe si no existen)
    let usersCount = 0;
    try {
      const r = await env.DB.prepare(`SELECT COUNT(*) as c FROM users WHERE status != 'deleted'`).first();
      usersCount = Number(r?.c || 0);
    } catch {}

    return json({
      success: true,
      stats: {
        usersCount,
        totalPayments: 0,
        totalRevenue: 0,
        pendingPayments: 0,
      },
    }, 200);
  }

  return json({ error: "Admin endpoint not found", path, method }, 404);
}

// ---------- app routes (mínimo, podés extender) ----------
async function handleAppRoutes(request, env, path, method) {
  try {
    await authenticateRequest(request, env, false);
  } catch {
    return json({ error: "Unauthorized" }, 401);
  }
  return json({ error: "App endpoint not found", path, method }, 404);
}

// ---------- health ----------
function healthPayload(env) {
  return {
    ok: true,
    version: "fixly-backend-unified",
    timestamp: nowISO(),
    configured: {
      ADMIN_DOMAIN: env?.ADMIN_DOMAIN ? true : false,
      APP_DOMAIN: env?.APP_DOMAIN ? true : false,
      JWT_SECRET: env?.JWT_SECRET ? true : false,
    },
    endpoints: [
      "GET  /health",
      "POST /api/auth/login",
      "POST /api/auth/logout",
      "POST /auth/public/register",
      "POST /api/auth/public/register",
      "POST /auth/forgot-password",
      "POST /api/auth/forgot-password",
      "GET  /api/admin/users",
      "POST /api/admin/users",
      "GET  /api/admin/stats",
      "GET  /api/admin/dashboard/stats",
      "GET  /api/stats",
      "GET  /stats",
    ],
  };
}

// ---------- Worker fetch ----------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const rawPath = decodeURIComponent(url.pathname);
    const path = rawPath.trim().replace(/\/+$/, "");
    const method = request.method;

    // Preflight
    if (method === "OPTIONS") {
      return __fix_handlePreflight(request, env);
    }

    // Health
    if (path === "/health" && method === "GET") {
      return __fix_withCORS(json(healthPayload(env), 200), request, env);
    }

    // Auth
    if ((path === "/api/auth/login" || path === "/auth/login") && method === "POST") {
      return __fix_withCORS(await handleLogin(request, env), request, env);
    }
    if (path === "/api/auth/logout" && method === "POST") {
      return __fix_withCORS(await handleLogout(request, env), request, env);
    }

    // Public register (APP)
    if ((path === "/auth/public/register" || path === "/api/auth/public/register") && method === "POST") {
      return __fix_withCORS(await handlePublicRegister(request, env), request, env);
    }

    // Forgot password
    if ((path === "/auth/forgot-password" || path === "/api/auth/forgot-password") && method === "POST") {
      return __fix_withCORS(await handleForgotPassword(request, env), request, env);
    }

    // Admin / App
    if (path.startsWith("/api/admin/")) {
      return __fix_withCORS(await handleAdminRoutes(request, env, path, method), request, env);
    }

    // aliases de stats (por si el front pide /stats sin /api/admin)
    if ((path === "/stats" || path === "/api/stats") && method === "GET") {
      return __fix_withCORS(await handleAdminRoutes(request, env, path, method), request, env);
    }

    if (path.startsWith("/api/app/") || path.startsWith("/api/devices")) {
      return __fix_withCORS(await handleAppRoutes(request, env, path, method), request, env);
    }

    return __fix_withCORS(json({ error: "Endpoint no encontrado", path, method }, 404), request, env);
  },
};
