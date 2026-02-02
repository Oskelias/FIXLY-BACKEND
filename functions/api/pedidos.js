// GET/POST /api/pedidos - Orders management (tenant + location scoped)
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
      `SELECT * FROM pedidos WHERE tenant_id = ? AND location_id = ? ORDER BY created_at DESC`
    ).bind(tenantId, locationId).all();

    return json({ success: true, pedidos: r.results });
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

    if (!data.cliente || !data.producto) {
      return json({ success: false, error: "Cliente and producto are required" }, 400);
    }

    const res = await env.DB.prepare(`
      INSERT INTO pedidos (
        tenant_id, location_id, cliente, telefono, producto, descripcion, precio_total, sena, estado, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      locationId,
      data.cliente,
      data.telefono || "",
      data.producto,
      data.descripcion || "",
      data.precio_total || 0,
      data.sena || 0,
      data.estado || "pendiente"
    ).run();

    return json({ success: true, id: res.meta.last_row_id });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
