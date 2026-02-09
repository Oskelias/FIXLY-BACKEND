// GET /auth/me - Returns current user info from token
import { json, verifyJWT } from "../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const auth = request.headers.get("Authorization");

    if (!auth || !auth.startsWith("Bearer ")) {
      return json({ success: false, error: "No authorization token provided" }, 401);
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
      return json({ success: false, error: "Session has been revoked" }, 401);
    }

    // Get fresh user data from DB
    const user = await env.DB.prepare(`
      SELECT id, username, email, role, plan, status, tenant_id, trial_ends_at, created_at, last_login
      FROM users
      WHERE id = ? AND status != 'deleted'
    `).bind(payload.userId).first();

    if (!user) {
      return json({ success: false, error: "User not found" }, 404);
    }

    // Check trial expiration
    if (user.status === "trial" && user.trial_ends_at) {
      if (new Date(user.trial_ends_at) < new Date()) {
        return json({ success: false, error: "Trial period has expired" }, 403);
      }
    }

    return json({
      success: true,
      user: {
        id: user.id,
        username: user.username || "",
        email: user.email || "",
        tenantId: user.tenant_id || "",
        role: user.role || "",
        plan: user.plan || "",
        status: user.status || "",
        trialEndsAt: user.trial_ends_at || null,
        createdAt: user.created_at || null,
        lastLogin: user.last_login || null
      }
    });
  } catch (err) {
    // JWT verification failed or expired
    return json({ success: false, error: err.message }, 401);
  }
}
