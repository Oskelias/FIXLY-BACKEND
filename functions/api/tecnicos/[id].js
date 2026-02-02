// GET/PUT/DELETE /api/tecnicos/:id - Technician detail (tenant + location scoped)
import { json, authenticateRequest, getLocationId } from "../../_lib.js";

export async function onRequestGet(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const locationId = getLocationId(request);
    if (!locationId) {
      return json({ success: false, error: "Location ID is required" }, 400);
    }

    const tecnico = await env.DB.prepare(
      `SELECT * FROM tecnicos WHERE id = ? AND tenant_id = ? AND location_id = ?`
    ).bind(id, tenantId, locationId).first();

    if (!tecnico) {
      return json({ success: false, error: "Tecnico not found" }, 404);
    }

    return json({ success: true, tecnico });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}

export async function onRequestPut(context) {
  const { request, env, params } = context;
  const { id } = params;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const updates = await request.json();
    const locationId = getLocationId(request, updates);
    if (!locationId) {
      return json({ success: false, error: "Location ID is required" }, 400);
    }

    const fields = [];
    const vals = [];

    for (const k of ["nombre", "telefono", "email", "especialidad", "estado"]) {
      if (updates[k] !== undefined) {
        fields.push(`${k} = ?`);
        vals.push(updates[k]);
      }
    }

    if (!fields.length) {
      return json({ success: false, error: "No valid fields to update" }, 400);
    }

    fields.push(`updated_at = datetime("now")`);
    vals.push(id, tenantId, locationId);

    await env.DB.prepare(
      `UPDATE tecnicos SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ? AND location_id = ?`
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
    const locationId = getLocationId(request);
    if (!locationId) {
      return json({ success: false, error: "Location ID is required" }, 400);
    }

    await env.DB.prepare(
      `DELETE FROM tecnicos WHERE id = ? AND tenant_id = ? AND location_id = ?`
    ).bind(id, tenantId, locationId).run();

    return json({ success: true });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
