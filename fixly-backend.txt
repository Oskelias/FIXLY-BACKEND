
// ==== FIX-CORS HELPERS (non-invasive) ====
function __fix_allowedOrigins(env) {
  const set = new Set();
  if (env && typeof env.ADMIN_DOMAIN === 'string' && env.ADMIN_DOMAIN.trim()) set.add(env.ADMIN_DOMAIN.trim());
  if (env && typeof env.APP_DOMAIN === 'string' && env.APP_DOMAIN.trim()) set.add(env.APP_DOMAIN.trim());
  if (env && typeof env.CORS_ALLOWED === 'string') {
    env.CORS_ALLOWED.split(',').forEach(o => { const v = (o||'').trim(); if (v) set.add(v); });
  }
  return set;
}
function __fix_withCORS(resp, request, env) {
  try {
    const origin = request.headers.get('Origin') || '';
    const allow = __fix_allowedOrigins(env);
    const h = new Headers(resp.headers);
    if (origin && allow.has(origin)) {
      h.set('Access-Control-Allow-Origin', origin);
      h.set('Vary', 'Origin');
      h.set('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
      h.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Tenant-Id');
      // h.set('Access-Control-Allow-Credentials', 'true'); // habilitar si usás cookies
    }
    return new Response(resp.body, { status: resp.status, headers: h });
  } catch (e) {
    return resp;
  }
}
function __fix_handlePreflight(request, env) {
  const origin = request.headers.get('Origin') || '';
  const allow = __fix_allowedOrigins(env);
  const headers = {
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Tenant-Id',
  };
  if (origin && allow.has(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Vary'] = 'Origin';
    // headers['Access-Control-Allow-Credentials'] = 'true'; // si cookies
  }
  return new Response(null, { status: 204, headers });
}
// ==== /FIX-CORS HELPERS ====

// ==== MP WEBHOOK HELPERS (safe, idempotent) ====
async function __mp_verifyHmac(raw, secret, signatureHeader) {
  try {
    const v1 = /v1=([^,]+)/.exec(signatureHeader || '')?.[1] || (signatureHeader || '');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret || ''), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(raw || ''));
    const digest = btoa(String.fromCharCode(...new Uint8Array(sig)));
    return __mp_timingSafeEqual(digest, v1);
  } catch (e) { return false; }
}
function __mp_timingSafeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let res = 0; for (let i = 0; i < a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}
async function __mp_upsertPaymentInDB(payment, env) {
  try {
    if (!env || !env.DB) return;
    const id = payment?.id?.toString?.() || '';
    const status = payment?.status || '';
    const email = payment?.payer?.email || '';
    if (!id) return;
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS pagos (id TEXT PRIMARY KEY, status TEXT, email TEXT, created_at TEXT)"
    ).run();
    await env.DB.prepare(
      "INSERT INTO pagos (id, status, email, created_at) VALUES (?1, ?2, ?3, datetime('now')) ON CONFLICT(id) DO UPDATE SET status=excluded.status, email=excluded.email"
    ).bind(id, status, email).run();
  } catch (e) {
    // swallow error to avoid 5xx from webhook path
  }
}
// ==== /MP WEBHOOK HELPERS ====


var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var DEFAULT_CORS = {
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Tenant-Id"
};
function corsHeadersFor(request, env) {
  const origin = request.headers.get("Origin");
  const allowAll = !env.ADMIN_DOMAIN && !env.APP_DOMAIN;
  const allowed = new Set([env.ADMIN_DOMAIN, env.APP_DOMAIN].filter(Boolean));
  if (allowAll) return { ...DEFAULT_CORS, "Access-Control-Allow-Origin": "*" };
  if (origin && allowed.has(origin)) {
    return { ...DEFAULT_CORS, "Access-Control-Allow-Origin": origin, "Vary": "Origin" };
  }
  return { ...DEFAULT_CORS, "Access-Control-Allow-Origin": "" };
}
__name(corsHeadersFor, "corsHeadersFor");
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers }
  });
}
__name(json, "json");
function nowISO() {
  return (/* @__PURE__ */ new Date()).toISOString();
}
__name(nowISO, "nowISO");
function generateTenantId() {
  return crypto.randomUUID();
}
__name(generateTenantId, "generateTenantId");
async function sha256Hex(input) {
  const enc = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(sha256Hex, "sha256Hex");
function b64urlFromUint8(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(b64urlFromUint8, "b64urlFromUint8");
function b64urlEncodeJSON(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  return b64urlFromUint8(bytes);
}
__name(b64urlEncodeJSON, "b64urlEncodeJSON");
function b64urlToUint8(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "==".slice((2 - b64url.length * 3 % 4) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
__name(b64urlToUint8, "b64urlToUint8");
async function generateJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64urlEncodeJSON(header);
  const encPayload = b64urlEncodeJSON(payload);
  const data = `${encHeader}.${encPayload}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
  const encSig = b64urlFromUint8(sig);
  return `${data}.${encSig}`;
}
__name(generateJWT, "generateJWT");
async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT format");
  const [encHeader, encPayload, encSig] = parts;
  const data = `${encHeader}.${encPayload}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("HMAC", key, b64urlToUint8(encSig), new TextEncoder().encode(data));
  if (!ok) throw new Error("Invalid JWT signature");
  const payload = JSON.parse(new TextDecoder().decode(b64urlToUint8(encPayload)));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1e3)) throw new Error("JWT has expired");
  return payload;
}
__name(verifyJWT, "verifyJWT");
async function hashPassword(password) {
  return sha256Hex(password);
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, hash) {
  return await hashPassword(password) === hash;
}
__name(verifyPassword, "verifyPassword");
async function authenticateRequest(request, env, requireAdmin = false) {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    throw new Error("No authorization token provided");
  }
  const token = auth.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
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
__name(authenticateRequest, "authenticateRequest");
async function manageDeviceSessions(user, env, token, deviceId, meta = {}) {
  const tokenHash = await sha256Hex(token);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1e3).toISOString();
  const sessions = await env.DB.prepare(
    `SELECT id, device_id, created_at FROM user_sessions 
     WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC`
  ).bind(user.id, user.tenant_id).all();
  if ((sessions.results?.length || 0) >= 3) {
    const oldest = sessions.results[sessions.results.length - 1];
    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE id = ?`
    ).bind(oldest.id).run();
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
__name(manageDeviceSessions, "manageDeviceSessions");
async function generateOrderNumber(tenantId, db) {
  const r = await db.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ?`).bind(tenantId).first();
  const next = (r?.count || 0) + 1;
  return `ORD-${String(next).padStart(4, "0")}`;
}
__name(generateOrderNumber, "generateOrderNumber");
async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) return json({ success: false, error: "Username and password are required" }, 400);
  const user = await env.DB.prepare(`SELECT * FROM users WHERE username = ? AND status != ?`).bind(username, "deleted").first();
  if (!user) return json({ success: false, error: "Invalid credentials" }, 401);
  const ok = await verifyPassword(password, user.password);
  if (!ok) return json({ success: false, error: "Invalid credentials" }, 401);
  if (user.status === "paused") return json({ success: false, error: "Account is paused" }, 403);
  if (user.status === "trial" && user.trial_ends_at) {
    if (new Date(user.trial_ends_at) < /* @__PURE__ */ new Date()) {
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
    exp: Math.floor(Date.now() / 1e3) + 24 * 60 * 60
  };
  const token = await generateJWT(payload, env.JWT_SECRET);
  await manageDeviceSessions(
    user,
    env,
    token,
    deviceId,
    {
      deviceName: request.headers.get("X-Device-Name") || "",
      ip: request.headers.get("CF-Connecting-IP") || "",
      ua: request.headers.get("User-Agent") || ""
    }
  );
  await env.DB.prepare(`UPDATE users SET last_login = datetime(?) WHERE id = ?`).bind(nowISO(), user.id).run();
  return json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      tenantId: user.tenant_id,
      role: user.role,
      plan: user.plan,
      status: user.status,
      redirectUrl: user.role === "admin" ? "/admin" : "/app"
    }
  });
}
__name(handleLogin, "handleLogin");
async function handleLogout(request, env) {
  try {
    const payload = await authenticateRequest(request, env);
    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE user_id = ? AND tenant_id = ? AND device_id = ?`
    ).bind(payload.userId, payload.tenantId, payload.deviceId).run();
    return json({ success: true });
  } catch {
    return json({ success: true });
  }
}
__name(handleLogout, "handleLogout");
async function handleAdminRoutes(request, env, path, method, cors) {
  await authenticateRequest(request, env, true);
  if (path === "/api/admin/users" && method === "GET") {
    const users = await env.DB.prepare(`
      SELECT id, username, email, role, plan, status, trial_ends_at, created_at, last_login, tenant_id
      FROM users WHERE status != ? ORDER BY created_at DESC
    `).bind("deleted").all();
    return json({ success: true, users: users.results }, 200, cors);
  }
  if (path === "/api/admin/users" && method === "POST") {
    const { username, password, email, plan = "basic", status = "trial" } = await request.json();
    if (!username || !password) return json({ success: false, error: "Username and password are required" }, 400, cors);
    const exists = await env.DB.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
    if (exists) return json({ success: false, error: "Username already exists" }, 409, cors);
    const hashed = await hashPassword(password);
    const tenantId = generateTenantId();
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1e3).toISOString();
    const res = await env.DB.prepare(`
      INSERT INTO users (username, password, email, tenant_id, role, plan, status, trial_ends_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(username, hashed, email || "", tenantId, "user", plan, status, trialEndsAt).run();
    return json({ success: true, userId: res.meta.last_row_id, tenantId }, 200, cors);
  }
  if (/^\/api\/admin\/user\/([^\/]+)$/.test(path) && method === "PUT") {
    const username = path.split("/").pop();
    const updates = await request.json();
    const fields = [];
    const vals = [];
    for (const k of ["email", "plan", "status"]) {
      if (updates[k] !== void 0) {
        fields.push(`${k} = ?`);
        vals.push(updates[k]);
      }
    }
    if (updates.extend_trial_days) {
      const u = await env.DB.prepare(`SELECT trial_ends_at FROM users WHERE username = ?`).bind(username).first();
      const cur = u?.trial_ends_at ? new Date(u.trial_ends_at) : /* @__PURE__ */ new Date();
      const next = new Date(cur.getTime() + updates.extend_trial_days * 864e5);
      fields.push("trial_ends_at = ?");
      vals.push(next.toISOString());
    }
    if (!fields.length) return json({ success: false, error: "No valid fields to update" }, 400, cors);
    fields.push(`updated_at = datetime("now")`);
    vals.push(username);
    await env.DB.prepare(`UPDATE users SET ${fields.join(", ")} WHERE username = ? AND status != 'deleted'`).bind(...vals).run();
    return json({ success: true }, 200, cors);
  }
  if (/^\/api\/admin\/user\/([^\/]+)$/.test(path) && method === "DELETE") {
    const username = path.split("/").pop();
    await env.DB.prepare(`UPDATE users SET status = ?, updated_at = datetime("now") WHERE username = ?`).bind("deleted", username).run();
    return json({ success: true }, 200, cors);
  }
  if (/^\/api\/admin\/user\/([^\/]+)\/pause$/.test(path) && method === "PUT") {
    const username = path.split("/")[4];
    const { action } = await request.json();
    const newStatus = action === "pause" ? "paused" : "active";
    await env.DB.prepare(`UPDATE users SET status = ?, updated_at = datetime("now") WHERE username = ?`).bind(newStatus, username).run();
    return json({ success: true }, 200, cors);
  }
  if (path === "/api/admin/payments" && method === "GET") {
    return json({ success: true, payments: [], statistics: { totalPayments: 0, totalAmount: 0, pendingPayments: 0 } }, 200, cors);
  }
  if (path === "/api/admin/reports/financial" && method === "GET") {
    const url = new URL(request.url);
    const period = url.searchParams.get("period") || "month";
    return json({
      success: true,
      period,
      summary: { totalRevenue: 0, totalTransactions: 0, averageTransaction: 0 },
      charts: { revenueByPlan: { basic: 0, pro: 0, enterprise: 0 } },
      recentPayments: []
    }, 200, cors);
  }
  return json({ error: "Admin endpoint not found" }, 404, cors);
}
__name(handleAdminRoutes, "handleAdminRoutes");
async function handleAppRoutes(request, env, path, method, cors) {
  const user = await authenticateRequest(request, env);
  const tenantId = user.tenantId;
  if (path === "/api/app/dashboard" && method === "GET") {
    const stats = await env.DB.batch([
      env.DB.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ?`).bind(tenantId),
      env.DB.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ? AND estado = ?`).bind(tenantId, "diagnosticando"),
      env.DB.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ? AND estado = ?`).bind(tenantId, "listo"),
      env.DB.prepare(`SELECT COUNT(*) as count FROM clientes WHERE tenant_id = ?`).bind(tenantId)
    ]);
    return json({
      success: true,
      stats: {
        totalReparaciones: stats[0].results[0]?.count || 0,
        enProceso: stats[1].results[0]?.count || 0,
        listos: stats[2].results[0]?.count || 0,
        totalClientes: stats[3].results[0]?.count || 0
      }
    }, 200, cors);
  }
  if (path === "/api/app/reparaciones" && method === "GET") {
    const r = await env.DB.prepare(`SELECT * FROM reparaciones WHERE tenant_id = ? ORDER BY created_at DESC`).bind(tenantId).all();
    return json({ success: true, reparaciones: r.results }, 200, cors);
  }
  if (path === "/api/app/reparaciones" && method === "POST") {
    const data = await request.json();
    if (!data.cliente || !data.equipo) return json({ success: false, error: "Cliente and equipo are required" }, 400, cors);
    const ordenId = await generateOrderNumber(tenantId, env.DB);
    const res = await env.DB.prepare(`
      INSERT INTO reparaciones (
        tenant_id, orden_id, cliente, telefono, equipo, problema, 
        estado, tecnico, costo, anticipo, observaciones, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      ordenId,
      data.cliente,
      data.telefono || "",
      data.equipo,
      data.problema || "",
      data.estado || "recibido",
      data.tecnico || "",
      data.costo || 0,
      data.anticipo || 0,
      data.observaciones || ""
    ).run();
    return json({ success: true, id: res.meta.last_row_id, ordenId }, 200, cors);
  }
  if (/^\/api\/app\/reparaciones\/(\d+)$/.test(path) && method === "PUT") {
    const id = path.split("/").pop();
    const u = await request.json();
    const fields = [];
    const vals = [];
    for (const k of ["estado", "tecnico", "problema", "costo", "anticipo", "observaciones"]) {
      if (u[k] !== void 0) {
        fields.push(`${k} = ?`);
        vals.push(u[k]);
      }
    }
    if (!fields.length) return json({ success: false, error: "No valid fields to update" }, 400, cors);
    fields.push(`updated_at = datetime("now")`);
    vals.push(id, tenantId);
    await env.DB.prepare(`UPDATE reparaciones SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ?`).bind(...vals).run();
    return json({ success: true }, 200, cors);
  }
  if (/^\/api\/app\/reparaciones\/(\d+)$/.test(path) && method === "DELETE") {
    const id = path.split("/").pop();
    await env.DB.prepare(`DELETE FROM reparaciones WHERE id = ? AND tenant_id = ?`).bind(id, tenantId).run();
    return json({ success: true }, 200, cors);
  }
  if (path === "/api/app/clientes" && method === "GET") {
    const r = await env.DB.prepare(`SELECT * FROM clientes WHERE tenant_id = ? ORDER BY nombre ASC`).bind(tenantId).all();
    return json({ success: true, clientes: r.results }, 200, cors);
  }
  if (path === "/api/app/clientes" && method === "POST") {
    const data = await request.json();
    if (!data.nombre) return json({ success: false, error: "Nombre is required" }, 400, cors);
    const res = await env.DB.prepare(`
      INSERT INTO clientes (tenant_id, nombre, telefono, email, direccion, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(tenantId, data.nombre, data.telefono || "", data.email || "", data.direccion || "").run();
    return json({ success: true, id: res.meta.last_row_id }, 200, cors);
  }
  if (path === "/api/app/pedidos" && method === "GET") {
    const r = await env.DB.prepare(`SELECT * FROM pedidos WHERE tenant_id = ? ORDER BY created_at DESC`).bind(tenantId).all();
    return json({ success: true, pedidos: r.results }, 200, cors);
  }
  if (path === "/api/app/pedidos" && method === "POST") {
    const data = await request.json();
    if (!data.cliente || !data.producto) return json({ success: false, error: "Cliente and producto are required" }, 400, cors);
    const res = await env.DB.prepare(`
      INSERT INTO pedidos (
        tenant_id, cliente, telefono, producto, descripcion, precio_total, sena, estado, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      data.cliente,
      data.telefono || "",
      data.producto,
      data.descripcion || "",
      data.precio_total || 0,
      data.sena || 0,
      "pendiente"
    ).run();
    return json({ success: true, id: res.meta.last_row_id }, 200, cors);
  }
  if (path === "/api/devices" && method === "GET") {
    const u = await authenticateRequest(request, env);
    const r = await env.DB.prepare(`
      SELECT device_id, device_name, ip_address, user_agent, created_at, expires_at, last_activity
      FROM user_sessions WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC
    `).bind(u.userId, u.tenantId).all();
    return json({ success: true, devices: r.results }, 200, cors);
  }
  if (path === "/api/devices/revoke" && method === "POST") {
    const u = await authenticateRequest(request, env);
    const { deviceId } = await request.json();
    if (!deviceId) return json({ success: false, error: "deviceId required" }, 400, cors);
    await env.DB.prepare(`DELETE FROM user_sessions WHERE user_id = ? AND tenant_id = ? AND device_id = ?`).bind(u.userId, u.tenantId, deviceId).run();
    return json({ success: true }, 200, cors);
  }
  return json({ error: "App endpoint not found" }, 404, cors);
}
__name(handleAppRoutes, "handleAppRoutes");
var TELEGRAM_CONFIG = {
  BOT_TOKEN: "7659942257:AAE1ajAek4aC86fQqTWWhoOYmpCkhv0b0Oc",
  CHAT_ID: "1819527108",
  API_URL: "https://api.telegram.org/bot"
};
function getCorsHeaders_Landing(request) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };
}
__name(getCorsHeaders_Landing, "getCorsHeaders_Landing");
async function sendTelegramNotification(text, extra = {}) {
  try {
    const response = await fetch(`${TELEGRAM_CONFIG.API_URL}${TELEGRAM_CONFIG.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: TELEGRAM_CONFIG.CHAT_ID, text, parse_mode: "HTML", ...extra })
    });
    const result = await response.json();
    if (!response.ok) return { success: false, error: result };
    return { success: true, result };
  } catch (error) {
    return { success: false, error: error.message };
  }
}
__name(sendTelegramNotification, "sendTelegramNotification");
async function sendEmail(to, subject, html) {
  try {
    const response = await fetch("https://api.mailchannels.net/tx/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: "noreply@fixlytaller.com", name: "Fixly Taller" },
        subject,
        content: [{ type: "text/html", value: html }]
      })
    });
    if (!response.ok) return false;
    return true;
  } catch {
    return false;
  }
}
__name(sendEmail, "sendEmail");
function makeUsernameSeed(email, empresa) {
  return (empresa || email.split("@")[0]).toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 8);
}
__name(makeUsernameSeed, "makeUsernameSeed");
function randUpper(n) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  return Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
}
__name(randUpper, "randUpper");
async function handleLeadRegistro(request, env) {
  try {
    const { taller, propietario, email, telefono, ciudad } = await request.json();
    if (!taller || !propietario || !email) {
      return json({ success: false, error: "Faltan datos requeridos: taller, propietario, email" }, 400, getCorsHeaders_Landing(request));
    }
    const leadId = "lead_" + Date.now();
    const leadData = { leadId, taller: (taller || "").slice(0, 50), propietario: (propietario || "").slice(0, 50), email, telefono: telefono || "", ciudad: ciudad || "" };
    await env.FIXLY_USERS.put(`lead_${leadId}`, JSON.stringify(leadData));
    const telegramText = [
      "\u{1F195} <b>Nuevo Lead - Fixly Taller</b>",
      "",
      `\u{1F3E2} <b>Taller:</b> ${taller}`,
      `\u{1F464} <b>Propietario:</b> ${propietario}`,
      `\u{1F4E7} <b>Email:</b> ${email}`,
      `\u{1F4F1} <b>Tel\xE9fono:</b> ${telefono || "No proporcionado"}`,
      `\u{1F4CD} <b>Ciudad:</b> ${ciudad || "No proporcionada"}`,
      "",
      `\u{1F194} <b>ID:</b> ${leadId}`,
      `\u23F0 <b>Fecha:</b> ${(/* @__PURE__ */ new Date()).toLocaleString("es-ES")}`,
      "",
      "\u{1F447} <b>Acciones disponibles:</b>"
    ].join("\n");
    const telegramResult = await sendTelegramNotification(telegramText, {
      reply_markup: {
        inline_keyboard: [
          [{ text: "\u2705 Crear usuario + credenciales", callback_data: `approve_${leadId}` }],
          [{ text: "\u274C Rechazar lead", callback_data: `reject_${leadId}` }],
          [{ text: "\u{1F4CB} Ver detalles completos", callback_data: `details_${leadId}` }]
        ]
      }
    });
    return json({
      success: true,
      leadId,
      telegramSent: telegramResult.success,
      message: telegramResult.success ? "Lead registrado y notificaci\xF3n enviada a Telegram" : "Lead registrado pero fall\xF3 notificaci\xF3n Telegram"
    }, 200, getCorsHeaders_Landing(request));
  } catch (err) {
    return json({ success: false, error: err.message, details: "Error interno del servidor" }, 500, getCorsHeaders_Landing(request));
  }
}
__name(handleLeadRegistro, "handleLeadRegistro");
async function approveLeadAndSendCreds(leadId, env) {
  try {
    const leadDataStr = await env.FIXLY_USERS.get(`lead_${leadId}`);
    if (!leadDataStr) throw new Error(`Lead ${leadId} no encontrado`);
    const leadData = JSON.parse(leadDataStr);
    const seed = makeUsernameSeed(leadData.email, leadData.taller);
    let username = seed, i = 1;
    while (await env.FIXLY_USERS.get("user_" + username)) username = seed + i++;
    const tempPass = randUpper(8);
    const userData = {
      username,
      password: tempPass,
      email: leadData.email,
      empresa: leadData.taller,
      telefono: leadData.telefono,
      propietario: leadData.propietario,
      ciudad: leadData.ciudad,
      tipo: "starter",
      tenantId: "tenant_" + Date.now(),
      fechaCreacion: (/* @__PURE__ */ new Date()).toISOString(),
      fechaExpiracion: new Date(Date.now() + 15 * 24 * 60 * 60 * 1e3).toISOString(),
      activo: true,
      creadoDesde: "lead_" + leadId
    };
    await env.FIXLY_USERS.put("user_" + username, JSON.stringify(userData));
    const emailHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #667eea;">\u{1F389} \xA1Bienvenido a Fixly Taller!</h2>
        <p>Hola <strong>${leadData.propietario}</strong>,</p>
        <p>Tu cuenta para <strong>${leadData.taller}</strong> ya est\xE1 activa con <strong>15 d\xEDas de prueba gratuita</strong>.</p>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
          <h3>\u{1F511} Credenciales de Acceso</h3>
          <p><strong>Usuario:</strong> <code>${username}</code></p>
          <p><strong>Contrase\xF1a:</strong> <code>${tempPass}</code></p>
          <p><strong>URL de acceso:</strong> <a href="https://app.fixlytaller.com">app.fixlytaller.com</a></p>
        </div>
        <p>\u2728 <strong>\xA1Ya puedes empezar a usar el sistema!</strong></p>
        <p>Saludos,<br><strong>Equipo Fixly Taller</strong></p>
      </div>
    `;
    const emailSent = await sendEmail(leadData.email, "\u{1F527} \xA1Tu cuenta Fixly Taller est\xE1 lista! - Credenciales de acceso", emailHtml);
    await sendTelegramNotification([
      "\u{1F389} <b>\xA1Usuario creado exitosamente!</b>",
      "",
      `\u2705 <b>Credenciales enviadas a:</b> ${leadData.email}`,
      `\u{1F464} <b>Usuario:</b> ${username}`,
      `\u{1F511} <b>Password:</b> ${tempPass}`,
      `\u{1F3E2} <b>Empresa:</b> ${leadData.taller}`,
      `\u{1F468}\u200D\u{1F4BC} <b>Propietario:</b> ${leadData.propietario}`,
      "",
      `\u{1F4E7} <b>Email enviado:</b> ${emailSent ? "\u2705 S\xED" : "\u274C No"}`,
      `\u23F0 <b>Creado:</b> ${(/* @__PURE__ */ new Date()).toLocaleString("es-ES")}`,
      "",
      "\u{1F3AF} <b>El usuario puede acceder inmediatamente a app.fixlytaller.com</b>"
    ].join("\n"));
    await env.FIXLY_USERS.delete(`lead_${leadId}`);
    return { success: true, username, emailSent };
  } catch (err) {
    await sendTelegramNotification([
      "\u274C <b>Error procesando lead</b>",
      "",
      `\u{1F194} <b>Lead ID:</b> ${leadId}`,
      `\u{1F6AB} <b>Error:</b> ${err.message}`,
      `\u23F0 ${(/* @__PURE__ */ new Date()).toLocaleString("es-ES")}`
    ].join("\n"));
    return { success: false, error: err.message };
  }
}
__name(approveLeadAndSendCreds, "approveLeadAndSendCreds");
async function handleTestTelegram(request) {
  const r = await sendTelegramNotification([
    "\u{1F9EA} <b>Test de Telegram</b>",
    "",
    "\u2705 Si ves este mensaje, las notificaciones funcionan correctamente",
    `\u23F0 ${(/* @__PURE__ */ new Date()).toLocaleString("es-ES")}`
  ].join("\n"));
  return json({ success: true, message: "Test enviado a Telegram", telegramResult: r }, 200, getCorsHeaders_Landing(request));
}
__name(handleTestTelegram, "handleTestTelegram");
function healthPayload() {
  return {
    status: "ok",
    version: "2.0.0-unified",
    timestamp: nowISO(),
    endpoints: [
      // Landing/Telegram
      "GET  /test-telegram",
      "POST /api/lead-registro",
      "POST /telegram/callback",
      // Backend auth/admin/app
      "GET  /health",
      "POST /api/auth/login",
      "POST /api/auth/logout",
      "GET  /api/admin/users",
      "POST /api/admin/users",
      "PUT  /api/admin/user/:username",
      "DELETE /api/admin/user/:username",
      "PUT  /api/admin/user/:username/pause",
      "GET  /api/app/dashboard",
      "GET  /api/app/reparaciones",
      "POST /api/app/reparaciones",
      "PUT  /api/app/reparaciones/:id",
      "DELETE /api/app/reparaciones/:id",
      "GET  /api/app/clientes",
      "POST /api/app/clientes",
      "GET  /api/app/pedidos",
      "POST /api/app/pedidos",
      "GET  /api/devices",
      "POST /api/devices/revoke"
    ]
  };
}
__name(healthPayload, "healthPayload");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const rawPath = decodeURIComponent(url.pathname);
const path = rawPath.trim().replace(/\/+$/, '');
    const method = request.method;
    

async function handleMPWebhook(request, env) {
  const signature = request.headers.get("x-signature");
  const requestId = request.headers.get("x-request-id");
  if (!signature || !requestId) return json({ ok:false, error:"missing headers" }, 400);

  const raw = await request.text(); // read once
  const ok = await __mp_verifyHmac(raw, env.MP_WEBHOOK_SECRET, signature);
  if (!ok) return json({ ok:false, error:"invalid signature" }, 401);

  let payload;
  try { payload = JSON.parse(raw); } catch (_) { return json({ ok:false, error:"bad json" }, 400); }
  const type = payload?.type;
  const id = payload?.data?.id;

  if (type === "payment" && id) {
    const r = await fetch(`https://api.mercadopago.com/v1/payments/${id}`, {
      headers: { Authorization: `Bearer ${env.MP_ACCESS_TOKEN}` }
    });
    if (!r.ok) return json({ ok:false, error:"mp fetch error" }, 502);
    const payment = await r.json();
    await __mp_upsertPaymentInDB(payment, env); // idempotent
    return json({ ok:true });
  }

  return json({ ok:true, ignored:true });
}
if (method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", ...DEFAULT_CORS } });
    // Webhook Mercado Pago (server-to-server)
    if (path === "/webhooks/mercadopago" && method === "POST") {
      return await handleMPWebhook(request, env);
    }

    }
    if (path === "/test-telegram" && method === "GET") return __fix_withCORS(await handleTestTelegram(request), request, env);
    if (path === "/api/lead-registro" && method === "POST") return __fix_withCORS(await handleLeadRegistro(request, env), request, env);
    if (path === "/telegram/callback" && method === "POST") {
      try {
        const body = await request.json();
        const data = body.callback_query?.data;
        if (data?.startsWith("approve_")) {
          const leadId = data.replace("approve_", "");
          await approveLeadAndSendCreds(leadId, env);
        } else if (data?.startsWith("reject_")) {
          const leadId = data.replace("reject_", "");
          await sendTelegramNotification([
            "\u274C <b>Lead rechazado</b>",
            "",
            `\u{1F194} <b>Lead ID:</b> ${leadId}`,
            `\u23F0 ${(/* @__PURE__ */ new Date()).toLocaleString("es-ES")}`
          ].join("\n"));
          await env.FIXLY_USERS.delete(`lead_${leadId}`);
        } else if (data?.startsWith("details_")) {
          const leadId = data.replace("details_", "");
          const leadDataStr = await env.FIXLY_USERS.get(`lead_${leadId}`);
          if (leadDataStr) {
            const leadData = JSON.parse(leadDataStr);
            await sendTelegramNotification([
              "\u{1F4CB} <b>Detalles del Lead</b>",
              "",
              `\u{1F194} <b>ID:</b> ${leadData.leadId}`,
              `\u{1F3E2} <b>Taller:</b> ${leadData.taller}`,
              `\u{1F464} <b>Propietario:</b> ${leadData.propietario}`,
              `\u{1F4E7} <b>Email:</b> ${leadData.email}`,
              `\u{1F4F1} <b>Tel\xE9fono:</b> ${leadData.telefono || "No proporcionado"}`,
              `\u{1F4CD} <b>Ciudad:</b> ${leadData.ciudad || "No proporcionada"}`
            ].join("\n"));
          }
        }
        return json({ ok: true });
      } catch (error) {
        return json({ ok: false, error: error.message }, 500);
      }
    }
    if (path === "/health" && method === "GET") {
      return json(healthPayload(), 200, corsHeadersFor(request, env));
    }
    if (path === "/api/auth/login" && method === "POST")
  return __fix_withCORS(await handleLogin(request, env), request, env);

// Alias canónico
if (path === "/auth/public/login" && method === "POST")
  return __fix_withCORS(await handleLogin(request, env), request, env);

// Alias adicional usado por el front
if (path === "/auth/login" && method === "POST")
    if (path === "/api/auth/login" && method === "POST") return __fix_withCORS(await handleLogin(request, env), request, env);

  return __fix_withCORS(await handleLogin(request, env), request, env); return __fix_withCORS(await handleLogin(request, env), request, env);
    if (path === "/api/auth/logout" && method === "POST") return __fix_withCORS(await handleLogout(request, env), request, env);
    // === Adapter para consola: /admin/users (GET/POST) ===
if (path === "/admin/users") {
  const cors = corsHeadersFor(request, env);

  // ---- GET: normaliza a { success: true, data: { users: [...] } }
  if (method === "GET") {
    const req2 = new Request(new URL("/api/admin/users", request.url), {
      method:"GET",
      headers: request.headers
    });
    const upstream = await handleAdminRoutes(req2, env, "/api/admin/users", "GET", cors);

    let data = {};
    try { const raw = await upstream.text(); data = raw ? JSON.parse(raw) : {}; } catch {}

    const rows = Array.isArray(data.users) ? data.users
               : (Array.isArray(data.items) ? data.items : []);

    const users = rows.map(u => ({
      id: u.id ?? u.user_id ?? null,
      email: u.email ?? "",
      name: u.name ?? u.username ?? "",
      role: (typeof u.role === "string")
              ? (u.role.toLowerCase() === "admin"  ? "Administrador"
                : u.role.toLowerCase() === "viewer" ? "Visualizador"
                : "Operador")
              : "Operador",
      active: (u.active !== undefined) ? !!u.active
            : (u.status ? String(u.status).toLowerCase() === "active" : true),
      lastAccess: u.last_login ?? u.updated_at ?? null
    }));

    return __fix_withCORS(json({ success: true, data: { users } }, 200, cors), request, env);
  }

  // ---- POST: crear usuario (con fallback directo a D1) ----
  if (method === "POST") {
    // Acepta JSON, FormData o x-www-form-urlencoded
    async function readPayload(req){
      try { const j = await req.clone().json(); if (j && (j.email || j.userEmail || j.password || j.userPassword)) return j; } catch {}
      try {
        const fd = await req.clone().formData();
        const obj = {}; for (const [k,v] of fd.entries()) obj[k] = typeof v === "string" ? v : "";
        if (obj.email || obj.userEmail || obj.password || obj.userPassword) return obj;
      } catch {}
      try {
        const txt = await req.clone().text();
        const obj = {}; new URLSearchParams(txt).forEach((v,k)=> obj[k]=v);
        if (obj.email || obj.userEmail || obj.password || obj.userPassword) return obj;
      } catch {}
      return {};
    }

    function toBool(v){
      if (typeof v === "boolean") return v;
      if (v == null) return false;
      const s = String(v).toLowerCase();
      return s === "true" || s === "1" || s === "on" || s === "yes";
    }

    const body = await readPayload(request);
    const email = (body.email || body.userEmail || body.mail || "").trim();
    const name  = (body.name  || body.userName || body.fullname || body.fullName || "").trim();
    const pass  = (body.password || body.userPassword || body.pass || "").toString();
    const roleUi  = (body.role || body.userRole || "").toString(); // "Administrador" | "Operador" | "Visualizador"
    const active = ('active' in body) ? toBool(body.active)
                   : ('userActive' in body) ? toBool(body.userActive) : true;

    if (!email || !pass) {
      return __fix_withCORS(json({ success:false, message:"email y password requeridos" }, 400, cors), request, env);
    }

    // 1) Intento normal contra tu API interna
    try {
      const base = (email.split("@")[0] || "user").replace(/[^a-z0-9._-]/gi,"").toLowerCase() || "user";
      const suf  = Math.random().toString(36).slice(2,7);
      const username = `${base}-${suf}`;

      const hdrs = new Headers(request.headers);
      hdrs.set("content-type","application/json");

      const payload = {
        username,
        password: pass,
        email,
        role: roleUi,
        plan: "basic",
        status: active ? "active" : "paused",
        name,
        active
      };

      const req2 = new Request(new URL("/api/admin/users", request.url), {
        method: "POST",
        headers: hdrs,
        body: JSON.stringify(payload)
      });
      const upstream = await handleAdminRoutes(req2, env, "/api/admin/users", "POST", cors);

      if (upstream.status >= 200 && upstream.status < 300) {
        const data = await (async ()=>{ try{ const t=await upstream.text(); return t?JSON.parse(t):{}; }catch{ return {}; } })();
        return __fix_withCORS(json({ success:true, ...data }, 201, cors), request, env);
      }
    } catch (_) { /* seguimos al fallback */ }

    // 2) Fallback directo a D1
    try {
      // email duplicado
      const dup = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
      if (dup) return __fix_withCORS(json({ success:false, message:"El email ya está en uso" }, 409, cors), request, env);

      // username único
      function baseFromEmail(e){ return (e.split("@")[0] || "user").replace(/[^a-z0-9._-]/gi,"").toLowerCase() || "user"; }
      const base = baseFromEmail(email);
      let username = `${base}-${Math.random().toString(36).slice(2,7)}`;
      for (let i=0; i<8; i++){
        const ex = await env.DB.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
        if (!ex) break;
        username = `${base}-${Math.random().toString(36).slice(2,7)}`;
      }

      // normalizar rol
      const roleNorm = (()=> {
        const r = roleUi.toString().toLowerCase();
        if (["administrador","admin","owner"].includes(r)) return "admin";
        if (["visualizador","viewer"].includes(r)) return "viewer";
        return "user"; // Operador
      })();

      // hash, tenant, trial
      const hashed = await hashPassword(pass);
      const tenantId = crypto.randomUUID();
      const trialEndsAt = new Date(Date.now() + 7*24*60*60*1000).toISOString();

      // insert
      const res = await env.DB.prepare(`
        INSERT INTO users (username, password, email, tenant_id, role, plan, status, trial_ends_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(username, hashed, email, tenantId, roleNorm, "basic", active ? "active" : "paused", trialEndsAt).run();

      return __fix_withCORS(json({ success:true, userId: res.meta.last_row_id, tenantId }, 201, cors), request, env);
    } catch (e) {
      return __fix_withCORS(json({ success:false, message:`Error creando usuario: ${e.message}` }, 500, cors), request, env);
    }
  }

  return __fix_withCORS(json({ error:"Method not allowed" }, 405, cors), request, env);
}
// === /Adapter consola ===
if (path.startsWith("/api/admin/")) return __fix_withCORS(await handleAdminRoutes(request, env, path, method, corsHeadersFor(request, env)), request, env);
    if (path.startsWith("/api/app/") || path.startsWith("/api/devices")) {
      return __fix_withCORS(await handleAppRoutes(request, env, path, method, corsHeadersFor(request, env)), request, env);
    }
    return __fix_withCORS(json({ error: "Endpoint no encontrado", path, method, available: healthPayload().endpoints }, 404), request, env);
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map 
