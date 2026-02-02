// GET/POST /api/historial - History entries (tenant + location scoped)
import { json, authenticateRequest, getLocationId } from "../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const locationId = getLocationId(request);
    if (!locationId) {
      return json({ success: false, error: "Location ID is required" }, 400);
    }

    const r = await env.DB.prepare(
      `SELECT * FROM historial WHERE tenant_id = ? AND location_id = ? ORDER BY created_at DESC`
    ).bind(tenantId, locationId).all();

    return json({ success: true, historial: r.results });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const data = await request.json();
    const locationId = getLocationId(request, data);
    if (!locationId) {
      return json({ success: false, error: "Location ID is required" }, 400);
    }

    if (!data.referencia_tipo || !data.referencia_id || !data.descripcion) {
      return json({ success: false, error: "referencia_tipo, referencia_id, and descripcion are required" }, 400);
    }

    const res = await env.DB.prepare(`
      INSERT INTO historial (
        tenant_id, location_id, referencia_tipo, referencia_id, descripcion, created_at
      ) VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      locationId,
      data.referencia_tipo,
      data.referencia_id,
      data.descripcion
    ).run();

    return json({ success: true, id: res.meta.last_row_id });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
