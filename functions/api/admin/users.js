// GET/POST /api/admin/users - Admin users management
import { json, authenticateRequest, hashPassword } from "../../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true); // requireAdmin = true

    const users = await env.DB.prepare(`
      SELECT id, username, email, role, plan, status, trial_ends_at, created_at, last_login, tenant_id
      FROM users WHERE status != 'deleted' ORDER BY created_at DESC
    `).all();

    return json({ success: true, users: users.results });
  } catch (err) {
    const status = err.message.includes("Admin") ? 403 : 401;
    return json({ success: false, error: err.message }, status);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true);

    const { username, password, email, plan = "basic", status = "trial" } = await request.json();

    if (!username || !password) {
      return json({ success: false, error: "Username and password are required" }, 400);
    }

    // Check if username exists
    const exists = await env.DB.prepare(`SELECT id FROM users WHERE username = ?`).bind(username).first();
    if (exists) {
      return json({ success: false, error: "Username already exists" }, 409);
    }

    const hashed = await hashPassword(password);
    const tenantId = crypto.randomUUID();
    const trialEndsAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

    const res = await env.DB.prepare(`
      INSERT INTO users (username, password, email, tenant_id, role, plan, status, trial_ends_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(username, hashed, email || "", tenantId, "user", plan, status, trialEndsAt).run();

    return json({ success: true, userId: res.meta.last_row_id, tenantId });
  } catch (err) {
    const status = err.message.includes("Admin") ? 403 : err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
