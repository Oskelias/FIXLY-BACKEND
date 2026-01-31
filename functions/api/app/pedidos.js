// GET/POST /api/app/pedidos - Orders management
import { json, authenticateRequest } from "../../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;

    const r = await env.DB.prepare(
      `SELECT * FROM pedidos WHERE tenant_id = ? ORDER BY created_at DESC`
    ).bind(tenantId).all();

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

    if (!data.cliente || !data.producto) {
      return json({ success: false, error: "Cliente and producto are required" }, 400);
    }

    const res = await env.DB.prepare(`
      INSERT INTO pedidos (
        tenant_id, cliente, telefono, producto, descripcion, precio_total, sena, estado, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(
      tenantId,
      data.cliente,
      data.telefono || "",
      data.producto,
      data.descripcion || "",
      data.precio_total || 0,
      data.sena || 0,
      "pendiente"
    ).run();

    return json({ success: true, id: res.meta.last_row_id });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
