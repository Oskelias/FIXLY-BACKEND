// PUT /api/admin/user/:username/pause - Pause/unpause user
import { json, authenticateRequest } from "../../../../_lib.js";

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const { username } = params;

  try {
    await authenticateRequest(request, env, true);

    const { action } = await request.json();
    const newStatus = action === "pause" ? "paused" : "active";

    await env.DB.prepare(
      `UPDATE users SET status = ?, updated_at = datetime("now") WHERE username = ?`
    ).bind(newStatus, username).run();

    return json({ success: true });
  } catch (err) {
    const status = err.message.includes("Admin") ? 403 : 401;
    return json({ success: false, error: err.message }, status);
  }
}
