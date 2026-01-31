// POST /api/devices/revoke - Revoke a device session
import { json, authenticateRequest } from "../../_lib.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);
    const { deviceId } = await request.json();

    if (!deviceId) {
      return json({ success: false, error: "deviceId required" }, 400);
    }

    await env.DB.prepare(
      `DELETE FROM user_sessions WHERE user_id = ? AND tenant_id = ? AND device_id = ?`
    ).bind(user.userId, user.tenantId, deviceId).run();

    return json({ success: true });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
