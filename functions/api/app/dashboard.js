// GET /api/app/dashboard - App dashboard stats
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

    const stats = await env.DB.batch([
      env.DB.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ? AND location_id = ?`)
        .bind(tenantId, locationId),
      env.DB.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ? AND location_id = ? AND estado = ?`)
        .bind(tenantId, locationId, "diagnosticando"),
      env.DB.prepare(`SELECT COUNT(*) as count FROM reparaciones WHERE tenant_id = ? AND location_id = ? AND estado = ?`)
        .bind(tenantId, locationId, "listo"),
      env.DB.prepare(`SELECT COUNT(*) as count FROM clientes WHERE tenant_id = ? AND location_id = ?`)
        .bind(tenantId, locationId)
    ]);

    return json({
      success: true,
      stats: {
        totalReparaciones: stats[0].results[0]?.count || 0,
        enProceso: stats[1].results[0]?.count || 0,
        listos: stats[2].results[0]?.count || 0,
        totalClientes: stats[3].results[0]?.count || 0
      }
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
