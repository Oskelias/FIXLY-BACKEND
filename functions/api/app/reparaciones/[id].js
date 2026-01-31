// PUT/DELETE /api/app/reparaciones/:id - Update or delete repair
import { json, authenticateRequest } from "../../../_lib.js";

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const updates = await request.json();

    const fields = [];
    const vals = [];

    for (const k of ["estado", "tecnico", "problema", "costo", "anticipo", "observaciones"]) {
      if (updates[k] !== undefined) {
        fields.push(`${k} = ?`);
        vals.push(updates[k]);
      }
    }

    if (!fields.length) {
      return json({ success: false, error: "No valid fields to update" }, 400);
    }

    fields.push(`updated_at = datetime("now")`);
    vals.push(id, tenantId);

    await env.DB.prepare(
      `UPDATE reparaciones SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ?`
    ).bind(...vals).run();

    return json({ success: true });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}

export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;

    await env.DB.prepare(
      `DELETE FROM reparaciones WHERE id = ? AND tenant_id = ?`
    ).bind(id, tenantId).run();

    return json({ success: true });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
