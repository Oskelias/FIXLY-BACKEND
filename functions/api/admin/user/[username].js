// PUT/DELETE /api/admin/user/:username - Update or delete user
import { json, authenticateRequest } from "../../../_lib.js";

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const { username } = params;

  try {
    await authenticateRequest(request, env, true);

    const updates = await request.json();
    const fields = [];
    const vals = [];

    for (const k of ["email", "plan", "status"]) {
      if (updates[k] !== undefined) {
        fields.push(`${k} = ?`);
        vals.push(updates[k]);
      }
    }

    if (updates.extend_trial_days) {
      const u = await env.DB.prepare(`SELECT trial_ends_at FROM users WHERE username = ?`).bind(username).first();
      const cur = u?.trial_ends_at ? new Date(u.trial_ends_at) : new Date();
      const next = new Date(cur.getTime() + updates.extend_trial_days * 86400000);
      fields.push("trial_ends_at = ?");
      vals.push(next.toISOString());
    }

    if (!fields.length) {
      return json({ success: false, error: "No valid fields to update" }, 400);
    }

    fields.push(`updated_at = datetime("now")`);
    vals.push(username);

    await env.DB.prepare(
      `UPDATE users SET ${fields.join(", ")} WHERE username = ? AND status != 'deleted'`
    ).bind(...vals).run();

    return json({ success: true });
  } catch (err) {
    const status = err.message.includes("Admin") ? 403 : 401;
    return json({ success: false, error: err.message }, status);
  }
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const { username } = params;

  try {
    await authenticateRequest(request, env, true);

    await env.DB.prepare(
      `UPDATE users SET status = 'deleted', updated_at = datetime("now") WHERE username = ?`
    ).bind(username).run();

    return json({ success: true });
  } catch (err) {
    const status = err.message.includes("Admin") ? 403 : 401;
    return json({ success: false, error: err.message }, status);
  }
}
