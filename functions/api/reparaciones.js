// GET/POST /api/reparaciones - Repairs management (tenant + location scoped)
import { json, authenticateRequest, generateOrderNumber, getLocationId } from "../_lib.js";

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
      `SELECT * FROM reparaciones
       WHERE tenant_id = ? AND location_id = ?
       ORDER BY created_at DESC`
    ).bind(tenantId, locationId).all();

    return json({ success: true, reparaciones: r.results });
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

    if (!data.cliente || !data.equipo) {
      return json({ success: false, error: "Cliente and equipo are required" }, 400);
    }

    const ordenId = await generateOrderNumber(tenantId, locationId, env.DB);

    const res = await env.DB.prepare(`
      INSERT INTO reparaciones (
        tenant_id, location_id, orden_id, cliente, telefono, equipo, problema,
        estado, tecnico, costo, anticipo, observaciones, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      locationId,
      ordenId,
      data.cliente,
      data.telefono || "",
      data.equipo,
      data.problema || "",
      data.estado || "recibido",
      data.tecnico || "",
      data.costo || 0,
      data.anticipo || 0,
      data.observaciones || ""
    ).run();

    return json({ success: true, id: res.meta.last_row_id, ordenId });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
