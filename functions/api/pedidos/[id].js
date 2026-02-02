// GET/PUT/DELETE /api/pedidos/:id - Order detail (tenant + location scoped)
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

    const pedido = await env.DB.prepare(
      `SELECT * FROM pedidos WHERE id = ? AND tenant_id = ? AND location_id = ?`
    ).bind(id, tenantId, locationId).first();

    if (!pedido) {
      return json({ success: false, error: "Pedido not found" }, 404);
    }

    return json({ success: true, pedido });
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

    for (const k of [
      "cliente",
      "telefono",
      "producto",
      "descripcion",
      "precio_total",
      "sena",
      "estado"
    ]) {
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
      `UPDATE pedidos SET ${fields.join(", ")} WHERE id = ? AND tenant_id = ? AND location_id = ?`
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
      `DELETE FROM pedidos WHERE id = ? AND tenant_id = ? AND location_id = ?`
    ).bind(id, tenantId, locationId).run();

    return json({ success: true });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
