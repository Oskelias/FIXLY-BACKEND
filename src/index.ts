import worker from "../index.js";

type Env = {
  DB: D1Database;
  AUTH_SECRET?: string;
  JWT_SECRET?: string;
  QUEUE_SECRET?: string;
  ADMIN_BOOTSTRAP_EMAIL?: string;
  ADMIN_DOMAIN?: string;
  APP_DOMAIN?: string;
  CORS_ALLOWED?: string;
};

const DEFAULT_ALLOWED_ORIGINS = [
  "https://admin.fixlytaller.com",
  "https://app.fixlytaller.com",
  "https://fixlytaller.com"
];

const DEFAULT_PERMISSIONS: Record<string, string[]> = {
  free: ["repairs", "settings"],
  pro: ["repairs", "settings", "dashboard", "history", "clients", "whatsapp", "orders_form"],
  business: ["repairs", "settings", "dashboard", "history", "clients", "whatsapp", "orders_form"]
};

const DEFAULT_TEMPLATES: Array<{ key: string; body: string }> = [
  {
    key: "repair_created",
    body: "Hola {{name}}, recibimos tu reparación {{orderId}}. Te avisaremos novedades. Fixly Taller."
  },
  {
    key: "repair_status_changed",
    body: "Hola {{name}}, tu reparación {{orderId}} cambió a: {{status}}. Fixly Taller."
  },
  {
    key: "repair_ready",
    body: "Hola {{name}}, tu reparación {{orderId}} está lista para retirar. Fixly Taller."
  },
  {
    key: "repair_delivered",
    body: "Hola {{name}}, tu reparación {{orderId}} fue entregada. Gracias por elegir Fixly Taller."
  }
];

function jsonResponse(data: unknown, status = 200, headers: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...headers }
  });
}

function buildAllowedOrigins(env: Env): Set<string> {
  const allowed = new Set(DEFAULT_ALLOWED_ORIGINS);
  if (env.ADMIN_DOMAIN) allowed.add(env.ADMIN_DOMAIN);
  if (env.APP_DOMAIN) allowed.add(env.APP_DOMAIN);
  if (env.CORS_ALLOWED) {
    env.CORS_ALLOWED.split(",")
      .map((value) => value.trim())
      .filter(Boolean)
      .forEach((value) => allowed.add(value));
  }
  return allowed;
}

function corsHeaders(request: Request, env: Env): HeadersInit {
  const origin = request.headers.get("Origin") ?? "";
  const allow = buildAllowedOrigins(env);
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };
  if (origin && allow.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  return headers;
}

function withCors(response: Response, request: Request, env: Env): Response {
  const headers = new Headers(response.headers);
  const cors = corsHeaders(request, env);
  Object.entries(cors).forEach(([key, value]) => headers.set(key, value));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^\w\s-]/g, "")
    .trim()
    .replace(/[\s_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function getAuthSecret(env: Env): string {
  const secret = env.AUTH_SECRET || env.JWT_SECRET;
  if (!secret) {
    throw new Error("AUTH_SECRET is not configured");
  }
  return secret;
}

function b64urlFromUint8(u8: Uint8Array): string {
  let s = "";
  for (let i = 0; i < u8.length; i += 1) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToUint8(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "==".slice((2 - b64url.length * 3 % 4) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) u8[i] = bin.charCodeAt(i);
  return u8;
}

async function signToken(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const encodedHeader = b64urlFromUint8(headerBytes);
  const encodedPayload = b64urlFromUint8(payloadBytes);
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
  const encodedSig = b64urlFromUint8(signature);
  return `${data}.${encodedSig}`;
}

async function verifyToken(token: string, secret: string): Promise<Record<string, unknown>> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token");
  const [encodedHeader, encodedPayload, encodedSig] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const ok = await crypto.subtle.verify("HMAC", key, b64urlToUint8(encodedSig), new TextEncoder().encode(data));
  if (!ok) throw new Error("Invalid token signature");
  const payload = JSON.parse(new TextDecoder().decode(b64urlToUint8(encodedPayload)));
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }
  return payload;
}

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return `pbkdf2:100000:${b64urlFromUint8(salt)}:${b64urlFromUint8(rawKey)}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (!stored) return false;
  const [scheme, iterStr, saltB64, hashB64] = stored.split(":");
  if (scheme !== "pbkdf2" || !iterStr || !saltB64 || !hashB64) return false;
  const iterations = Number(iterStr);
  if (!Number.isFinite(iterations)) return false;
  const salt = b64urlToUint8(saltB64);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  return b64urlFromUint8(rawKey) === hashB64;
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  try {
    return (await request.json()) as Record<string, unknown>;
  } catch {
    throw new Error("Invalid JSON body");
  }
}

async function ensureSchema(env: Env): Promise<{ tenants: string[]; users: string[] }> {
  const tenantsInfo = await env.DB.prepare("PRAGMA table_info(tenants)").all();
  const usersInfo = await env.DB.prepare("PRAGMA table_info(users)").all();
  const tenants = (tenantsInfo.results || []).map((row) => String(row.name));
  const users = (usersInfo.results || []).map((row) => String(row.name));

  if (!tenants.length) {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        slug TEXT NOT NULL UNIQUE,
        plan TEXT NOT NULL DEFAULT 'free',
        created_at TEXT NOT NULL
      )`
    ).run();
  }

  if (!users.length) {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'owner',
        created_at TEXT NOT NULL
      )`
    ).run();
  }

  if (tenants.length) {
    if (!tenants.includes("plan")) {
      await env.DB.prepare("ALTER TABLE tenants ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'").run();
      tenants.push("plan");
    }
    if (!tenants.includes("slug")) {
      await env.DB.prepare("ALTER TABLE tenants ADD COLUMN slug TEXT").run();
      tenants.push("slug");
    }
  }

  if (users.length) {
    if (!users.includes("password_hash")) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN password_hash TEXT").run();
      users.push("password_hash");
    }
  }

  return { tenants, users };
}

async function ensureWhatsappSchema(env: Env): Promise<void> {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS whatsapp_settings (
      tenant_id TEXT PRIMARY KEY,
      enabled INTEGER NOT NULL DEFAULT 0,
      provider TEXT,
      sender_id TEXT,
      token TEXT,
      webhook_secret TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )`
  ).run();

  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS message_templates (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      key TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'whatsapp',
      body TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      UNIQUE (tenant_id, key)
    )`
  ).run();

  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS message_queue (
      id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      to_phone TEXT NOT NULL,
      template_key TEXT,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'queued',
      attempts INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TEXT NOT NULL,
      last_error TEXT,
      created_at TEXT NOT NULL,
      sent_at TEXT
    )`
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_message_queue_status_next ON message_queue (status, next_attempt_at)"
  ).run();

  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY,
      tenant_id TEXT,
      type TEXT,
      data_json TEXT,
      created_at TEXT NOT NULL
    )`
  ).run();
}

async function ensureUniqueSlug(env: Env, slug: string, columns: string[]): Promise<string> {
  if (!columns.includes("slug")) {
    return slug;
  }
  let candidate = slug || "taller";
  let suffix = 0;
  while (true) {
    const existing = await env.DB.prepare("SELECT id FROM tenants WHERE slug = ? LIMIT 1")
      .bind(candidate)
      .first();
    if (!existing) return candidate;
    suffix += 1;
    candidate = `${slug || "taller"}-${suffix}`;
  }
}

function getUserNameColumn(columns: string[]): string {
  if (columns.includes("name")) return "name";
  if (columns.includes("username")) return "username";
  return "name";
}

function getUserPasswordColumn(columns: string[]): string {
  if (columns.includes("password_hash")) return "password_hash";
  if (columns.includes("password")) return "password";
  return "password_hash";
}

function getTenantNameColumn(columns: string[]): string {
  if (columns.includes("name")) return "name";
  if (columns.includes("nombre")) return "nombre";
  return "name";
}

function getTenantPlanColumn(columns: string[]): string | null {
  return columns.includes("plan") ? "plan" : null;
}

function getTenantSlugColumn(columns: string[]): string | null {
  return columns.includes("slug") ? "slug" : null;
}

function getTenantCreatedColumn(columns: string[]): string | null {
  return columns.includes("created_at") ? "created_at" : null;
}

function getUserCreatedColumn(columns: string[]): string | null {
  return columns.includes("created_at") ? "created_at" : null;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function permissionsForPlan(plan?: string): string[] {
  if (!plan) return DEFAULT_PERMISSIONS.free;
  return DEFAULT_PERMISSIONS[plan] || DEFAULT_PERMISSIONS.free;
}

function hasWhatsappFeature(plan?: string): boolean {
  return plan === "pro" || plan === "business";
}

function maskToken(token?: string | null): string | null {
  if (!token) return null;
  if (token.length <= 8) return `${token.slice(0, 2)}****`;
  return `${token.slice(0, 4)}****${token.slice(-4)}`;
}

function normalizePhone(raw: string): string {
  let normalized = raw.trim().replace(/[\s-]/g, "");
  if (normalized && !normalized.startsWith("+")) {
    normalized = `+${normalized}`;
  }
  return normalized;
}

function renderTemplate(body: string, payload: Record<string, unknown>): string {
  return body.replace(/{{\s*([a-zA-Z0-9_]+)\s*}}/g, (_, key: string) => {
    const value = payload[key];
    if (value === undefined || value === null) return "";
    return String(value);
  });
}

function nowISO(): string {
  return new Date().toISOString();
}

async function fetchTenantById(
  env: Env,
  tenantId: string,
  columns: string[]
): Promise<{ id: string; name: string; slug?: string; plan?: string } | null> {
  const nameColumn = getTenantNameColumn(columns);
  const fields = [`id`, `${nameColumn} as name`];
  const slugColumn = getTenantSlugColumn(columns);
  const planColumn = getTenantPlanColumn(columns);
  if (slugColumn) fields.push(`${slugColumn} as slug`);
  if (planColumn) fields.push(`${planColumn} as plan`);
  const query = `SELECT ${fields.join(", ")} FROM tenants WHERE id = ? LIMIT 1`;
  const tenant = await env.DB.prepare(query).bind(tenantId).first();
  if (!tenant) return null;
  return {
    id: String(tenant.id),
    name: String(tenant.name || ""),
    slug: tenant.slug ? String(tenant.slug) : undefined,
    plan: tenant.plan ? String(tenant.plan) : undefined
  };
}

async function fetchUserById(env: Env, userId: string, columns: string[]): Promise<{
  id: string;
  tenant_id: string;
  name?: string;
  email?: string;
  role?: string;
  status?: string | number | null;
  active?: string | number | null;
} | null> {
  const nameColumn = getUserNameColumn(columns);
  const fields = [
    "id",
    "tenant_id",
    `${nameColumn} as name`,
    "email",
    "role"
  ];
  if (columns.includes("status")) fields.push("status");
  if (columns.includes("active")) fields.push("active");
  const query = `SELECT ${fields.join(", ")} FROM users WHERE id = ? LIMIT 1`;
  const user = await env.DB.prepare(query).bind(userId).first();
  if (!user) return null;
  return {
    id: String(user.id),
    tenant_id: String(user.tenant_id),
    name: user.name ? String(user.name) : undefined,
    email: user.email ? String(user.email) : undefined,
    role: user.role ? String(user.role) : undefined,
    status: user.status ?? null,
    active: user.active ?? null
  };
}

async function getAuthContext(request: Request, env: Env): Promise<{
  userId: string;
  tenantId: string;
  plan?: string;
  role?: string;
  email?: string;
}> {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    throw new Error("unauthorized");
  }
  const secret = getAuthSecret(env);
  const payload = await verifyToken(auth.slice(7), secret);
  const userId = String(payload.userId || "");
  const tenantId = String(payload.tenantId || "");
  if (!userId || !tenantId) {
    throw new Error("unauthorized");
  }
  const { tenants } = await ensureSchema(env);
  const tenant = await fetchTenantById(env, tenantId, tenants);
  const { users } = await ensureSchema(env);
  const user = await fetchUserById(env, userId, users);
  return {
    userId,
    tenantId,
    plan: tenant?.plan || "free",
    role: user?.role,
    email: user?.email
  };
}

function isAdminUser(role?: string, email?: string | null, env?: Env): boolean {
  if (role === "admin" || role === "superadmin") return true;
  if (email && env?.ADMIN_BOOTSTRAP_EMAIL) {
    return email.toLowerCase() === env.ADMIN_BOOTSTRAP_EMAIL.toLowerCase();
  }
  return false;
}

async function getWhatsappSettings(env: Env, tenantId: string): Promise<{
  enabled: number;
  provider: string | null;
  sender_id: string | null;
  token: string | null;
  webhook_secret: string | null;
}> {
  await ensureWhatsappSchema(env);
  const row = await env.DB.prepare(
    "SELECT enabled, provider, sender_id, token, webhook_secret FROM whatsapp_settings WHERE tenant_id = ?"
  )
    .bind(tenantId)
    .first();
  if (!row) {
    return {
      enabled: 0,
      provider: null,
      sender_id: null,
      token: null,
      webhook_secret: null
    };
  }
  return {
    enabled: Number(row.enabled || 0),
    provider: row.provider ? String(row.provider) : null,
    sender_id: row.sender_id ? String(row.sender_id) : null,
    token: row.token ? String(row.token) : null,
    webhook_secret: row.webhook_secret ? String(row.webhook_secret) : null
  };
}

async function upsertWhatsappSettings(
  env: Env,
  tenantId: string,
  settings: {
    enabled: boolean;
    provider?: string;
    sender_id?: string;
    token?: string;
    webhook_secret?: string;
  }
): Promise<void> {
  await ensureWhatsappSchema(env);
  const now = nowISO();
  const existing = await env.DB.prepare("SELECT tenant_id FROM whatsapp_settings WHERE tenant_id = ?")
    .bind(tenantId)
    .first();
  const enabledValue = settings.enabled ? 1 : 0;
  const provider = settings.provider || null;
  const senderId = settings.sender_id || null;
  const token = settings.token || null;
  const webhookSecret = settings.webhook_secret || null;

  if (!existing) {
    await env.DB.prepare(
      `INSERT INTO whatsapp_settings
        (tenant_id, enabled, provider, sender_id, token, webhook_secret, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
    )
      .bind(tenantId, enabledValue, provider, senderId, token, webhookSecret, now, now)
      .run();
    return;
  }

  await env.DB.prepare(
    `UPDATE whatsapp_settings
     SET enabled = ?2, provider = ?3, sender_id = ?4, token = ?5, webhook_secret = ?6, updated_at = ?7
     WHERE tenant_id = ?1`
  )
    .bind(tenantId, enabledValue, provider, senderId, token, webhookSecret, now)
    .run();
}

async function enqueueMessage(env: Env, params: {
  tenantId: string;
  to: string;
  templateKey?: string | null;
  payload: Record<string, unknown>;
}): Promise<void> {
  await ensureWhatsappSchema(env);
  const id = crypto.randomUUID();
  const now = nowISO();
  await env.DB.prepare(
    `INSERT INTO message_queue
      (id, tenant_id, channel, to_phone, template_key, payload_json, status, attempts, next_attempt_at, created_at)
     VALUES (?1, ?2, 'whatsapp', ?3, ?4, ?5, 'queued', 0, ?6, ?7)`
  )
    .bind(
      id,
      params.tenantId,
      params.to,
      params.templateKey || null,
      JSON.stringify(params.payload),
      now,
      now
    )
    .run();
}

async function logAudit(env: Env, params: { tenantId?: string | null; type: string; data: Record<string, unknown> }) {
  await ensureWhatsappSchema(env);
  await env.DB.prepare(
    "INSERT INTO audit_log (id, tenant_id, type, data_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
  )
    .bind(
      crypto.randomUUID(),
      params.tenantId || null,
      params.type,
      JSON.stringify(params.data),
      nowISO()
    )
    .run();
}

async function getTableColumns(env: Env, table: string): Promise<string[]> {
  const info = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
  return (info.results || []).map((row) => String(row.name));
}

function isUserActive(row: { status?: string | number | null; active?: string | number | null }): boolean {
  if (row.active !== undefined && row.active !== null) {
    if (typeof row.active === "number") return row.active === 1;
    return String(row.active).toLowerCase() === "true" || String(row.active) === "1";
  }
  if (row.status !== undefined && row.status !== null) {
    return String(row.status).toLowerCase() === "active";
  }
  return true;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    if (path === "/internal/queue/process" && method === "POST") {
      const secretHeader = request.headers.get("X-Queue-Secret");
      if (!env.QUEUE_SECRET || secretHeader !== env.QUEUE_SECRET) {
        return withCors(jsonResponse({ ok: false, error: "unauthorized" }, 401), request, env);
      }
      await ensureWhatsappSchema(env);
      const now = nowISO();
      const batch = await env.DB.prepare(
        `SELECT id, tenant_id, to_phone, template_key, payload_json
         FROM message_queue
         WHERE status = 'queued' AND next_attempt_at <= ?1
         ORDER BY next_attempt_at ASC
         LIMIT 25`
      )
        .bind(now)
        .all();
      let sent = 0;
      let failed = 0;
      for (const item of batch.results || []) {
        const messageId = String(item.id);
        const tenantId = String(item.tenant_id);
        await env.DB.prepare("UPDATE message_queue SET status = 'sending' WHERE id = ?1")
          .bind(messageId)
          .run();
        const settings = await getWhatsappSettings(env, tenantId);
        if (!settings.enabled) {
          await env.DB.prepare(
            "UPDATE message_queue SET status = 'failed', last_error = ?2, attempts = attempts + 1, next_attempt_at = ?3 WHERE id = ?1"
          )
            .bind(messageId, "whatsapp_disabled", now)
            .run();
          failed += 1;
          continue;
        }
        let text = "";
        const payload = item.payload_json ? JSON.parse(String(item.payload_json)) : {};
        if (item.template_key) {
          const template = await env.DB.prepare(
            "SELECT body, enabled FROM message_templates WHERE tenant_id = ?1 AND key = ?2 LIMIT 1"
          )
            .bind(tenantId, String(item.template_key))
            .first();
          if (!template || Number(template.enabled) === 0) {
            await env.DB.prepare(
              "UPDATE message_queue SET status = 'failed', last_error = ?2, attempts = attempts + 1, next_attempt_at = ?3 WHERE id = ?1"
            )
              .bind(messageId, "template_disabled", now)
              .run();
            failed += 1;
            continue;
          }
          text = renderTemplate(String(template.body), payload);
        } else {
          text = String(payload.message || "");
        }

        if (settings.provider && settings.provider !== "mock") {
          const attemptsRow = await env.DB.prepare(
            "SELECT attempts FROM message_queue WHERE id = ?1"
          )
            .bind(messageId)
            .first();
          const attempts = Number(attemptsRow?.attempts || 0) + 1;
          const delayMinutes = Math.min(Math.pow(2, attempts), 60);
          const nextAttempt = new Date(Date.now() + delayMinutes * 60 * 1000).toISOString();
          const status = attempts >= 8 ? "dead" : "failed";
          await env.DB.prepare(
            "UPDATE message_queue SET status = ?2, attempts = ?3, next_attempt_at = ?4, last_error = ?5 WHERE id = ?1"
          )
            .bind(messageId, status, attempts, nextAttempt, "provider_not_configured")
            .run();
          failed += 1;
          continue;
        }

        await env.DB.prepare(
          "UPDATE message_queue SET status = 'sent', sent_at = ?2 WHERE id = ?1"
        )
          .bind(messageId, now)
          .run();
        await logAudit(env, {
          tenantId,
          type: "whatsapp_sent",
          data: { to: item.to_phone, text, template_key: item.template_key }
        });
        sent += 1;
      }
      return withCors(
        jsonResponse({ ok: true, processed: batch.results?.length || 0, sent, failed }),
        request,
        env
      );
    }

    if (path === "/health" && method === "GET") {
      return jsonResponse({ ok: true }, 200, corsHeaders(request, env));
    }

    if (path === "/auth/public/register" && method === "POST") {
      try {
        const payload = await readJson(request);
        const workshopName = String(payload.workshopName || payload.tallerNombre || "").trim();
        const ownerName = String(payload.ownerName || payload.ownerNombre || "").trim();
        const emailRaw = String(payload.email || "").trim();
        const phone = String(payload.phone || payload.telefono || "").trim();
        const city = String(payload.city || "").trim();
        const country = String(payload.country || "").trim();
        const password = String(payload.password || "");

        if (!workshopName || !ownerName || !emailRaw) {
          return jsonResponse(
            { ok: false, message: "workshopName, ownerName, email and password are required" },
            400,
            corsHeaders(request, env)
          );
        }

        if (!password) {
          return jsonResponse(
            { ok: false, message: "password is required" },
            400,
            corsHeaders(request, env)
          );
        }

        const { tenants, users } = await ensureSchema(env);
        const email = normalizeEmail(emailRaw);
        const existingUser = await env.DB.prepare("SELECT id FROM users WHERE lower(email) = ? LIMIT 1")
          .bind(email)
          .first();
        if (existingUser) {
          return jsonResponse({ ok: false, error: "email already registered" }, 409, corsHeaders(request, env));
        }

        const tenantId = crypto.randomUUID();
        const tenantNameColumn = getTenantNameColumn(tenants);
        const tenantPlanColumn = getTenantPlanColumn(tenants);
        const tenantSlugColumn = getTenantSlugColumn(tenants);
        const tenantCreatedColumn = getTenantCreatedColumn(tenants);
        const baseSlug = slugify(workshopName);
        const tenantSlug = await ensureUniqueSlug(env, baseSlug, tenants);
        const tenantColumns = ["id", tenantNameColumn];
        const tenantValues: (string | null)[] = [tenantId, workshopName];
        if (tenantSlugColumn) {
          tenantColumns.push(tenantSlugColumn);
          tenantValues.push(tenantSlug);
        }
        if (tenantPlanColumn) {
          tenantColumns.push(tenantPlanColumn);
          tenantValues.push("free");
        }
        if (tenantCreatedColumn) {
          tenantColumns.push(tenantCreatedColumn);
          tenantValues.push(new Date().toISOString());
        }
        const tenantInsert = `INSERT INTO tenants (${tenantColumns.join(", ")}) VALUES (${tenantColumns.map(() => "?").join(", ")})`;
        await env.DB.prepare(tenantInsert).bind(...tenantValues).run();

        const userId = crypto.randomUUID();
        const userNameColumn = getUserNameColumn(users);
        const passwordColumn = getUserPasswordColumn(users);
        const createdColumn = getUserCreatedColumn(users);
        const userColumns = ["id", "tenant_id", userNameColumn, "email", passwordColumn, "role"];
        const passwordHash = await hashPassword(password);
        const userValues: (string | null)[] = [
          userId,
          tenantId,
          ownerName,
          email,
          passwordHash,
          "admin"
        ];
        if (users.includes("phone")) {
          userColumns.push("phone");
          userValues.push(phone);
        } else if (users.includes("telefono")) {
          userColumns.push("telefono");
          userValues.push(phone);
        }
        if (users.includes("city")) {
          userColumns.push("city");
          userValues.push(city);
        } else if (users.includes("ciudad")) {
          userColumns.push("ciudad");
          userValues.push(city);
        }
        if (users.includes("country")) {
          userColumns.push("country");
          userValues.push(country);
        } else if (users.includes("pais")) {
          userColumns.push("pais");
          userValues.push(country);
        }
        if (createdColumn) {
          userColumns.push(createdColumn);
          userValues.push(new Date().toISOString());
        }
        const userInsert = `INSERT INTO users (${userColumns.join(", ")}) VALUES (${userColumns.map(() => "?").join(", ")})`;
        await env.DB.prepare(userInsert).bind(...userValues).run();

        const secret = getAuthSecret(env);
        const token = await signToken(
          {
            userId,
            tenantId,
            role: "admin",
            exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
          },
          secret
        );

        return jsonResponse(
          {
            ok: true,
            token,
            user: {
              id: userId,
              email,
              name: ownerName,
              role: "admin"
            },
            tenant: {
              id: tenantId,
              name: workshopName,
              slug: tenantSlug,
              plan: "free"
            }
          },
          201,
          corsHeaders(request, env)
        );
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "Unexpected error" },
          400,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/whatsapp/settings" && method === "GET") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!hasWhatsappFeature(authContext.plan)) {
          return jsonResponse({ ok: false, error: "feature_not_available" }, 403, corsHeaders(request, env));
        }
        const settings = await getWhatsappSettings(env, authContext.tenantId);
        return jsonResponse(
          {
            ok: true,
            settings: {
              enabled: settings.enabled,
              provider: settings.provider,
              sender_id: settings.sender_id,
              token: maskToken(settings.token),
              webhook_secret: settings.webhook_secret ? "****" : null
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch {
        return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
      }
    }

    if (path === "/whatsapp/settings" && method === "POST") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!hasWhatsappFeature(authContext.plan)) {
          return jsonResponse({ ok: false, error: "feature_not_available" }, 403, corsHeaders(request, env));
        }
        const payload = await readJson(request);
        const enabled = Boolean(payload.enabled);
        const provider = payload.provider ? String(payload.provider) : undefined;
        const senderId = payload.sender_id ? String(payload.sender_id) : undefined;
        const token = payload.token ? String(payload.token) : undefined;
        const webhookSecret = payload.webhook_secret ? String(payload.webhook_secret) : undefined;
        // TODO: encrypt token at rest before storing in D1.
        await upsertWhatsappSettings(env, authContext.tenantId, {
          enabled,
          provider,
          sender_id: senderId,
          token,
          webhook_secret: webhookSecret
        });
        const settings = await getWhatsappSettings(env, authContext.tenantId);
        return jsonResponse(
          {
            ok: true,
            settings: {
              enabled: settings.enabled,
              provider: settings.provider,
              sender_id: settings.sender_id,
              token: maskToken(settings.token),
              webhook_secret: settings.webhook_secret ? "****" : null
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "unauthorized" },
          401,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/whatsapp/test" && method === "POST") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!hasWhatsappFeature(authContext.plan)) {
          return jsonResponse({ ok: false, error: "feature_not_available" }, 403, corsHeaders(request, env));
        }
        const payload = await readJson(request);
        const to = payload.to ? normalizePhone(String(payload.to)) : "";
        const message = payload.message ? String(payload.message) : "";
        if (!to || !message) {
          return jsonResponse({ ok: false, error: "to and message are required" }, 400, corsHeaders(request, env));
        }
        await enqueueMessage(env, {
          tenantId: authContext.tenantId,
          to,
          templateKey: null,
          payload: { message }
        });
        return jsonResponse({ ok: true }, 202, corsHeaders(request, env));
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "unauthorized" },
          401,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/templates" && method === "GET") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!hasWhatsappFeature(authContext.plan)) {
          return jsonResponse({ ok: false, error: "feature_not_available" }, 403, corsHeaders(request, env));
        }
        const channel = url.searchParams.get("channel") || "whatsapp";
        await ensureWhatsappSchema(env);
        const rows = await env.DB.prepare(
          "SELECT id, key, channel, body, enabled, created_at FROM message_templates WHERE tenant_id = ?1 AND channel = ?2"
        )
          .bind(authContext.tenantId, channel)
          .all();
        return jsonResponse(
          { ok: true, templates: rows.results || [] },
          200,
          corsHeaders(request, env)
        );
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "unauthorized" },
          401,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/templates" && method === "POST") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!hasWhatsappFeature(authContext.plan)) {
          return jsonResponse({ ok: false, error: "feature_not_available" }, 403, corsHeaders(request, env));
        }
        const payload = await readJson(request);
        const key = payload.key ? String(payload.key) : "";
        const channel = payload.channel ? String(payload.channel) : "whatsapp";
        const body = payload.body ? String(payload.body) : "";
        const enabled = payload.enabled === undefined ? 1 : payload.enabled ? 1 : 0;
        if (!key || !body) {
          return jsonResponse({ ok: false, error: "key and body are required" }, 400, corsHeaders(request, env));
        }
        await ensureWhatsappSchema(env);
        const now = nowISO();
        const existing = await env.DB.prepare(
          "SELECT id FROM message_templates WHERE tenant_id = ?1 AND key = ?2 LIMIT 1"
        )
          .bind(authContext.tenantId, key)
          .first();
        if (existing) {
          await env.DB.prepare(
            "UPDATE message_templates SET body = ?3, channel = ?4, enabled = ?5 WHERE tenant_id = ?1 AND key = ?2"
          )
            .bind(authContext.tenantId, key, body, channel, enabled)
            .run();
        } else {
          await env.DB.prepare(
            `INSERT INTO message_templates (id, tenant_id, key, channel, body, enabled, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
          )
            .bind(crypto.randomUUID(), authContext.tenantId, key, channel, body, enabled, now)
            .run();
        }
        return jsonResponse({ ok: true }, 200, corsHeaders(request, env));
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "unauthorized" },
          401,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/templates/seed" && method === "POST") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!hasWhatsappFeature(authContext.plan)) {
          return jsonResponse({ ok: false, error: "feature_not_available" }, 403, corsHeaders(request, env));
        }
        await ensureWhatsappSchema(env);
        const existing = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM message_templates WHERE tenant_id = ?1 AND channel = 'whatsapp'"
        )
          .bind(authContext.tenantId)
          .first();
        if (!existing || Number(existing.count) === 0) {
          const now = nowISO();
          for (const template of DEFAULT_TEMPLATES) {
            await env.DB.prepare(
              `INSERT INTO message_templates (id, tenant_id, key, channel, body, enabled, created_at)
               VALUES (?1, ?2, ?3, 'whatsapp', ?4, 1, ?5)`
            )
              .bind(crypto.randomUUID(), authContext.tenantId, template.key, template.body, now)
              .run();
          }
        }
        return jsonResponse({ ok: true }, 200, corsHeaders(request, env));
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "unauthorized" },
          401,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/whatsapp/webhook" && method === "POST") {
      try {
        const tenantId = request.headers.get("X-Tenant-Id") || url.searchParams.get("tenantId") || "";
        if (!tenantId) {
          return withCors(jsonResponse({ ok: false, error: "tenant_id_required" }, 400), request, env);
        }
        const settings = await getWhatsappSettings(env, tenantId);
        const providedSecret =
          request.headers.get("X-Webhook-Secret") ||
          url.searchParams.get("secret") ||
          "";
        if (!settings.webhook_secret || settings.webhook_secret !== providedSecret) {
          return withCors(jsonResponse({ ok: false, error: "unauthorized" }, 403), request, env);
        }
        const payload = await readJson(request);
        await logAudit(env, { tenantId, type: "whatsapp_inbound", data: payload });
        return withCors(jsonResponse({ ok: true }, 200), request, env);
      } catch {
        return withCors(jsonResponse({ ok: false, error: "bad_request" }, 400), request, env);
      }
    }

    if (path === "/admin/dashboard" && method === "GET") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!isAdminUser(authContext.role, authContext.email, env)) {
          return jsonResponse({ ok: false, error: "forbidden" }, 403, corsHeaders(request, env));
        }
        return jsonResponse(
          {
            ok: true,
            dashboard: {
              totalRepairs: 24,
              openRepairs: 8,
              completedToday: 5,
              pendingOrders: 3
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch {
        return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
      }
    }

    if (path === "/admin/stats" && method === "GET") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!isAdminUser(authContext.role, authContext.email, env)) {
          return jsonResponse({ ok: false, error: "forbidden" }, 403, corsHeaders(request, env));
        }
        return jsonResponse(
          {
            ok: true,
            stats: {
              tenants_total: 12,
              users_total: 47,
              users_active: 41,
              payments_month: 15,
              revenue_month: 0
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch {
        return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
      }
    }

    if (path === "/admin/stats-legacy" && method === "GET") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!isAdminUser(authContext.role, authContext.email, env)) {
          return jsonResponse({ ok: false, error: "forbidden" }, 403, corsHeaders(request, env));
        }
        const tenantsCount = await env.DB.prepare("SELECT COUNT(*) as count FROM tenants").first();
        const usersCount = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
        let usersActive = Number(usersCount?.count || 0);
        const userColumns = await getTableColumns(env, "users");
        if (userColumns.includes("status") || userColumns.includes("active")) {
          const rows = await env.DB.prepare("SELECT status, active FROM users").all();
          usersActive = (rows.results || []).filter((row) =>
            isUserActive({
              status: row.status ?? null,
              active: row.active ?? null
            })
          ).length;
        }

        let paymentsMonth = 0;
        let revenueMonth = 0;
        const paymentColumns = await getTableColumns(env, "pagos");
        if (paymentColumns.length > 0) {
          // TODO: refine payment metrics once the payments schema is finalized.
          const startOfMonth = new Date();
          startOfMonth.setUTCDate(1);
          startOfMonth.setUTCHours(0, 0, 0, 0);
          const since = startOfMonth.toISOString();
          const paymentRows = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM pagos WHERE created_at >= ?1"
          )
            .bind(since)
            .first();
          paymentsMonth = Number(paymentRows?.count || 0);
          revenueMonth = 0;
        }

        return jsonResponse(
          {
            ok: true,
            stats: {
              tenants_total: Number(tenantsCount?.count || 0),
              users_total: Number(usersCount?.count || 0),
              users_active: usersActive,
              payments_month: paymentsMonth,
              revenue_month: revenueMonth
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch {
        return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
      }
    }

    if (path === "/admin/tenants" && method === "GET") {
      try {
        const authContext = await getAuthContext(request, env);
        if (!isAdminUser(authContext.role, authContext.email, env)) {
          return jsonResponse({ ok: false, error: "forbidden" }, 403, corsHeaders(request, env));
        }
        const tenantColumns = await getTableColumns(env, "tenants");
        const nameColumn = getTenantNameColumn(tenantColumns);
        const slugColumn = getTenantSlugColumn(tenantColumns);
        const planColumn = getTenantPlanColumn(tenantColumns);
        const createdColumn = getTenantCreatedColumn(tenantColumns);
        const fields = [
          "id",
          `${nameColumn} as name`
        ];
        if (slugColumn) fields.push(`${slugColumn} as slug`);
        if (planColumn) fields.push(`${planColumn} as plan`);
        if (createdColumn) fields.push(`${createdColumn} as created_at`);
        const rows = await env.DB.prepare(
          `SELECT ${fields.join(", ")} FROM tenants ORDER BY ${createdColumn || "rowid"} DESC LIMIT 200`
        ).all();
        const tenants = (rows.results || []).map((row) => ({
          id: String(row.id),
          name: row.name ? String(row.name) : "",
          slug: row.slug ? String(row.slug) : "",
          plan: row.plan ? String(row.plan) : "free",
          created_at: row.created_at ? String(row.created_at) : null
        }));
        return jsonResponse({ ok: true, tenants }, 200, corsHeaders(request, env));
      } catch {
        return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
      }
    }

    if (path === "/auth/public/login" && method === "POST") {
      try {
        const payload = await readJson(request);
        const emailRaw = String(payload.email || "").trim();
        const password = String(payload.password || "");
        if (!emailRaw || !password) {
          return jsonResponse(
            { ok: false, message: "email and password are required" },
            400,
            corsHeaders(request, env)
          );
        }

        const { tenants, users } = await ensureSchema(env);
        const email = normalizeEmail(emailRaw);
        const passwordColumn = getUserPasswordColumn(users);
        const userNameColumn = getUserNameColumn(users);
        const user = await env.DB.prepare(
          `SELECT id, tenant_id, ${userNameColumn} as name, email, ${passwordColumn} as password_hash, role FROM users WHERE lower(email) = ? LIMIT 1`
        )
          .bind(email)
          .first();

        if (!user || !user.password_hash) {
          return jsonResponse({ ok: false, error: "invalid credentials" }, 401, corsHeaders(request, env));
        }

        const valid = await verifyPassword(password, String(user.password_hash));
        if (!valid) {
          return jsonResponse({ ok: false, error: "invalid credentials" }, 401, corsHeaders(request, env));
        }

        const tenant = await fetchTenantById(env, String(user.tenant_id), tenants);

        const secret = getAuthSecret(env);
        const token = await signToken(
          {
            userId: user.id,
            tenantId: user.tenant_id,
            role: user.role || "owner",
            exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60
          },
          secret
        );

        return jsonResponse(
          {
            ok: true,
            token,
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
              role: user.role || "owner"
            },
            tenant: {
              id: tenant?.id || user.tenant_id,
              name: tenant?.name || "",
              slug: tenant?.slug || "",
              plan: tenant?.plan || "free"
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch (error) {
        return jsonResponse(
          { ok: false, error: error instanceof Error ? error.message : "Unexpected error" },
          400,
          corsHeaders(request, env)
        );
      }
    }

    if (path === "/me" && method === "GET") {
      try {
        const auth = request.headers.get("Authorization") || "";
        if (!auth.startsWith("Bearer ")) {
          return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
        }

        const secret = getAuthSecret(env);
        const payload = await verifyToken(auth.slice(7), secret);
        const userId = String(payload.userId || "");
        const tenantId = String(payload.tenantId || "");
        if (!userId || !tenantId) {
          return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
        }

        const { tenants, users } = await ensureSchema(env);
        const userNameColumn = getUserNameColumn(users);
        const user = await env.DB.prepare(
          `SELECT id, tenant_id, ${userNameColumn} as name, email, role FROM users WHERE id = ? LIMIT 1`
        )
          .bind(userId)
          .first();
        if (!user) {
          return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
        }
        const tenant = await fetchTenantById(env, tenantId, tenants);
        const plan = tenant?.plan || "free";
        return jsonResponse(
          {
            ok: true,
            user: {
              id: user.id,
              email: user.email,
              name: user.name,
              role: user.role || "owner"
            },
            tenant: {
              id: tenant?.id || tenantId,
              name: tenant?.name || "",
              slug: tenant?.slug || "",
              plan,
              permissions: permissionsForPlan(plan)
            }
          },
          200,
          corsHeaders(request, env)
        );
      } catch {
        return jsonResponse({ ok: false, error: "unauthorized" }, 401, corsHeaders(request, env));
      }
    }

    if (path.startsWith("/api/app/reparaciones/") && (method === "PUT" || method === "PATCH")) {
      const bodyText = await request.text();
      let payload: Record<string, unknown> = {};
      try {
        payload = bodyText ? (JSON.parse(bodyText) as Record<string, unknown>) : {};
      } catch {
        payload = {};
      }
      const statusNext = payload.estado ? String(payload.estado) : "";
      let authContext: { tenantId: string; plan?: string } | null = null;
      try {
        authContext = await getAuthContext(request, env);
      } catch {
        authContext = null;
      }
      let previousStatus = "";
      let repairRow: Record<string, unknown> | null = null;
      if (authContext && statusNext) {
        const repairId = path.split("/").pop() || "";
        repairRow = await env.DB.prepare(
          "SELECT id, orden_id, cliente, telefono, equipo, estado FROM reparaciones WHERE id = ?1 AND tenant_id = ?2 LIMIT 1"
        )
          .bind(repairId, authContext.tenantId)
          .first();
        previousStatus = repairRow?.estado ? String(repairRow.estado) : "";
      }
      const forwarded = await worker.fetch(
        new Request(request, { body: bodyText }),
        env,
        ctx
      );
      if (
        forwarded.ok &&
        authContext &&
        statusNext &&
        statusNext !== previousStatus &&
        hasWhatsappFeature(authContext.plan)
      ) {
        const settings = await getWhatsappSettings(env, authContext.tenantId);
        const phone = repairRow?.telefono ? normalizePhone(String(repairRow.telefono)) : "";
        if (settings.enabled && phone) {
          const templateKey = "repair_status_changed";
          const payloadData = {
            name: repairRow?.cliente || "",
            orderId: repairRow?.orden_id || repairRow?.id || "",
            status: statusNext,
            device: repairRow?.equipo || "",
            link: ""
          };
          await enqueueMessage(env, {
            tenantId: authContext.tenantId,
            to: phone,
            templateKey,
            payload: payloadData
          });
          await logAudit(env, {
            tenantId: authContext.tenantId,
            type: "repair_status_changed",
            data: {
              repairId: repairRow?.id || "",
              previousStatus,
              statusNext,
              to: phone
            }
          });
        }
      }
      return withCors(forwarded, request, env);
    }

    return withCors(await worker.fetch(request, env, ctx), request, env);
  }
};
