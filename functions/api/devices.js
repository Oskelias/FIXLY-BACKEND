// GET /api/devices - List user devices/sessions
import { json, authenticateRequest } from "../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);

    const r = await env.DB.prepare(`
      SELECT device_id, device_name, ip_address, user_agent, created_at, expires_at, last_activity
      FROM user_sessions WHERE user_id = ? AND tenant_id = ? ORDER BY created_at DESC
    `).bind(user.userId, user.tenantId).all();

    return json({ success: true, devices: r.results });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
