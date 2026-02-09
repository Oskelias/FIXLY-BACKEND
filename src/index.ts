import worker from "../index.js";

type Env = {
  DB: D1Database;
  AUTH_SECRET?: string;
  JWT_SECRET?: string;
  ADMIN_DOMAIN?: string;
  APP_DOMAIN?: string;
  CORS_ALLOWED?: string;
};

const DEFAULT_ALLOWED_ORIGINS = [
  "https://app.fixlytaller.com",
  "https://fixlytaller.com"
];

const DEFAULT_PERMISSIONS: Record<string, string[]> = {
  free: ["repairs", "settings"],
  pro: ["repairs", "settings", "dashboard", "history", "clients", "whatsapp", "orders_form"],
  business: ["repairs", "settings", "dashboard", "history", "clients", "whatsapp", "orders_form"]
};

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

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    if (path === "/health" && method === "GET") {
      return jsonResponse({ ok: true }, 200, corsHeaders(request, env));
    }

    if (path === "/auth/public/register" && method === "POST") {
      try {
        const payload = await readJson(request);
        const tallerNombre = String(payload.tallerNombre || "").trim();
        const ownerNombre = String(payload.ownerNombre || "").trim();
        const emailRaw = String(payload.email || "").trim();
        const password = String(payload.password || "");

        if (!tallerNombre || !ownerNombre || !emailRaw) {
          return jsonResponse(
            { ok: false, message: "tallerNombre, ownerNombre, and email are required" },
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
        const baseSlug = slugify(tallerNombre);
        const tenantSlug = await ensureUniqueSlug(env, baseSlug, tenants);
        const tenantColumns = ["id", tenantNameColumn];
        const tenantValues: (string | null)[] = [tenantId, tallerNombre];
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
          ownerNombre,
          email,
          passwordHash,
          "owner"
        ];
        if (users.includes("phone")) {
          userColumns.push("phone");
          userValues.push(payload.telefono ? String(payload.telefono) : "");
        } else if (users.includes("telefono")) {
          userColumns.push("telefono");
          userValues.push(payload.telefono ? String(payload.telefono) : "");
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
            role: "owner",
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
              name: ownerNombre,
              role: "owner"
            },
            tenant: {
              id: tenantId,
              name: tallerNombre,
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

    return worker.fetch(request, env, ctx);
  }
};
