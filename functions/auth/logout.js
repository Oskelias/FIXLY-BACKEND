// POST /auth/logout - Logout endpoint
import { json, verifyJWT } from "../_lib.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const auth = request.headers.get("Authorization");

    if (!auth || !auth.startsWith("Bearer ")) {
      return json({ success: true }); // Already logged out
    }

    const token = auth.slice(7);
    const payload = await verifyJWT(token, env.JWT_SECRET);

    // Delete session
    await env.DB.prepare(`
      DELETE FROM user_sessions
      WHERE user_id = ? AND tenant_id = ? AND device_id = ?
    `).bind(payload.userId, payload.tenantId, payload.deviceId).run();

    return json({ success: true });
  } catch {
    return json({ success: true }); // Already logged out
  }
}
