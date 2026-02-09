// GET/PUT/DELETE /api/users/:id - Individual user management
import { json, authenticateRequest, hashPassword, nowISO } from "../../_lib.js";

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    await authenticateRequest(request, env, true);

    console.log(`[API] GET /api/users/${id} - Fetching user`);

    const user = await env.DB.prepare(`
      SELECT
        id, username, email, role, plan, status,
        trial_ends_at, created_at, last_login, tenant_id
      FROM users
      WHERE id = ? AND status != 'deleted'
    `).bind(id).first();

    if (!user) {
      return json({ success: false, error: "Usuario no encontrado" }, 404);
    }

    return json({
      success: true,
      data: {
        id: user.id,
        name: user.username,
        email: user.email || "",
        role: user.role || "user",
        plan: user.plan || "basic",
        status: user.status || "active",
        active: user.status === "active" || user.status === "trial",
        trialEndsAt: user.trial_ends_at,
        createdAt: user.created_at,
        lastLogin: user.last_login,
        tenantId: user.tenant_id
      }
    });
  } catch (err) {
    console.error(`[API] GET /api/users/${id} - Error:`, err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    await authenticateRequest(request, env, true);

    const body = await request.json();
    const { name, email, password, role, active, plan } = body;

    console.log(`[API] PUT /api/users/${id} - Updating user:`, { name, email, role, active });

    // Check user exists
    const existing = await env.DB.prepare(
      `SELECT id, email FROM users WHERE id = ? AND status != 'deleted'`
    ).bind(id).first();

    if (!existing) {
      return json({ success: false, error: "Usuario no encontrado" }, 404);
    }

    // Build update query
    const updates = [];
    const values = [];

    if (name !== undefined) {
      updates.push("username = ?");
      values.push(name.trim());
    }

    if (email !== undefined) {
      // Check if email is already used by another user
      const emailExists = await env.DB.prepare(
        `SELECT id FROM users WHERE email = ? AND id != ? AND status != 'deleted'`
      ).bind(email.trim().toLowerCase(), id).first();

      if (emailExists) {
        return json({ success: false, error: "El email ya está en uso" }, 409);
      }

      updates.push("email = ?");
      values.push(email.trim().toLowerCase());
    }

    if (password !== undefined && password.length >= 4) {
      const hashedPassword = await hashPassword(password);
      updates.push("password = ?");
      values.push(hashedPassword);
    }

    if (role !== undefined) {
      const normalizedRole = role === "admin" || role === "Administrador" ? "admin" :
                            role === "viewer" || role === "Visualizador" ? "viewer" : "user";
      updates.push("role = ?");
      values.push(normalizedRole);
    }

    if (active !== undefined) {
      updates.push("status = ?");
      values.push(active ? "active" : "paused");
    }

    if (plan !== undefined) {
      updates.push("plan = ?");
      values.push(plan);
    }

    if (updates.length === 0) {
      return json({ success: false, error: "No hay campos para actualizar" }, 400);
    }

    updates.push("updated_at = datetime('now')");
    values.push(id);

    await env.DB.prepare(
      `UPDATE users SET ${updates.join(", ")} WHERE id = ?`
    ).bind(...values).run();

    // Fetch updated user
    const updated = await env.DB.prepare(`
      SELECT
        id, username, email, role, plan, status,
        trial_ends_at, created_at, last_login, tenant_id
      FROM users
      WHERE id = ?
    `).bind(id).first();

    console.log(`[API] PUT /api/users/${id} - User updated`);

    return json({
      success: true,
      data: {
        id: updated.id,
        name: updated.username,
        email: updated.email || "",
        role: updated.role || "user",
        plan: updated.plan || "basic",
        status: updated.status || "active",
        active: updated.status === "active" || updated.status === "trial",
        tenantId: updated.tenant_id
      }
    });
  } catch (err) {
    console.error(`[API] PUT /api/users/${id} - Error:`, err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    await authenticateRequest(request, env, true);

    console.log(`[API] DELETE /api/users/${id} - Deleting user`);

    // Check user exists
    const existing = await env.DB.prepare(
      `SELECT id FROM users WHERE id = ? AND status != 'deleted'`
    ).bind(id).first();

    if (!existing) {
      return json({ success: false, error: "Usuario no encontrado" }, 404);
    }

    // Soft delete
    await env.DB.prepare(
      `UPDATE users SET status = 'deleted', updated_at = datetime('now') WHERE id = ?`
    ).bind(id).run();

    // Also delete sessions
    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE user_id = ?`
    ).bind(id).run();

    console.log(`[API] DELETE /api/users/${id} - User deleted`);

    return json({
      success: true,
      data: { deleted: true, id: parseInt(id) }
    });
  } catch (err) {
    console.error(`[API] DELETE /api/users/${id} - Error:`, err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
