// GET/POST /api/users - Users management for admin panel
import { json, authenticateRequest, hashPassword, nowISO } from "../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    // Authenticate (admin only)
    await authenticateRequest(request, env, true);

    console.log("[API] GET /api/users - Fetching all users");

    const result = await env.DB.prepare(`
      SELECT
        id,
        username,
        email,
        role,
        plan,
        status,
        trial_ends_at,
        created_at,
        last_login,
        tenant_id
      FROM users
      WHERE status != 'deleted'
      ORDER BY created_at DESC
    `).all();

    const users = (result.results || []).map(u => ({
      id: u.id,
      name: u.username,
      email: u.email || "",
      role: u.role || "user",
      plan: u.plan || "basic",
      status: u.status || "active",
      active: u.status === "active" || u.status === "trial",
      trialEndsAt: u.trial_ends_at,
      createdAt: u.created_at,
      lastLogin: u.last_login,
      tenantId: u.tenant_id
    }));

    console.log(`[API] GET /api/users - Found ${users.length} users`);

    return json({
      success: true,
      data: { users }
    });
  } catch (err) {
    console.error("[API] GET /api/users - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    // Authenticate (admin only)
    await authenticateRequest(request, env, true);

    const body = await request.json();
    const { name, email, password, role = "user", active = true } = body;

    console.log("[API] POST /api/users - Creating user:", { name, email, role });

    // Validation
    if (!name || !name.trim()) {
      return json({ success: false, error: "El nombre es requerido" }, 400);
    }
    if (!email || !email.trim()) {
      return json({ success: false, error: "El email es requerido" }, 400);
    }
    if (!password || password.length < 4) {
      return json({ success: false, error: "La contraseña debe tener al menos 4 caracteres" }, 400);
    }

    // Check if email already exists
    const existingEmail = await env.DB.prepare(
      `SELECT id FROM users WHERE email = ? AND status != 'deleted'`
    ).bind(email.trim().toLowerCase()).first();

    if (existingEmail) {
      return json({ success: false, error: "El email ya está en uso" }, 409);
    }

    // Generate username from email
    const baseUsername = email.split("@")[0].toLowerCase().replace(/[^a-z0-9]/g, "") || "user";
    let username = baseUsername;
    let counter = 1;

    // Ensure unique username
    while (true) {
      const existing = await env.DB.prepare(
        `SELECT id FROM users WHERE username = ?`
      ).bind(username).first();
      if (!existing) break;
      username = `${baseUsername}${counter++}`;
      if (counter > 100) {
        username = `${baseUsername}_${crypto.randomUUID().slice(0, 8)}`;
        break;
      }
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Generate tenant ID
    const tenantId = crypto.randomUUID();

    // Calculate trial end date (7 days)
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    // Normalize role
    const normalizedRole = role === "admin" || role === "Administrador" ? "admin" :
                          role === "viewer" || role === "Visualizador" ? "viewer" : "user";

    // Insert user
    const result = await env.DB.prepare(`
      INSERT INTO users (
        username,
        password,
        email,
        tenant_id,
        role,
        plan,
        status,
        trial_ends_at,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      username,
      hashedPassword,
      email.trim().toLowerCase(),
      tenantId,
      normalizedRole,
      "basic",
      active ? "active" : "paused",
      trialEndsAt
    ).run();

    const newUser = {
      id: result.meta.last_row_id,
      name: username,
      email: email.trim().toLowerCase(),
      role: normalizedRole,
      plan: "basic",
      status: active ? "active" : "paused",
      active: active,
      tenantId: tenantId,
      trialEndsAt: trialEndsAt,
      createdAt: nowISO()
    };

    console.log("[API] POST /api/users - User created:", newUser.id);

    return json({
      success: true,
      data: newUser
    }, 201);
  } catch (err) {
    console.error("[API] POST /api/users - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 :
                   err.message.includes("UNIQUE") ? 409 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
