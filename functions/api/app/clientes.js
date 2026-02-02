// GET/POST /api/app/clientes - Clients management
import { json, authenticateRequest, getLocationId } from "../../_lib.js";

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
      `SELECT * FROM clientes WHERE tenant_id = ? AND location_id = ? ORDER BY nombre ASC`
    ).bind(tenantId, locationId).all();

    return json({ success: true, clientes: r.results });
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

    if (!data.nombre) {
      return json({ success: false, error: "Nombre is required" }, 400);
    }

    const res = await env.DB.prepare(`
      INSERT INTO clientes (tenant_id, location_id, nombre, telefono, email, direccion, created_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      locationId,
      data.nombre,
      data.telefono || "",
      data.email || "",
      data.direccion || ""
    ).run();

    return json({ success: true, id: res.meta.last_row_id });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
