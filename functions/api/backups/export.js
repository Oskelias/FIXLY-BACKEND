// POST /api/backups/export - Export tenant data to R2
import { json, authenticateRequest, getLocationId } from "../../_lib.js";

const TABLES = [
  "tenants",
  "locations",
  "clientes",
  "tecnicos",
  "reparaciones",
  "pedidos",
  "historial"
];

function buildQuery(table, tenantId, locationId) {
  const hasLocation = ["clientes", "tecnicos", "reparaciones", "pedidos", "historial", "locations"].includes(table);
  const where = [];
  const params = [];
  if (table !== "tenants") {
    where.push("tenant_id = ?");
    params.push(tenantId);
  } else {
    where.push("id = ?");
    params.push(tenantId);
  }
  if (hasLocation && locationId) {
    where.push("location_id = ?");
    params.push(locationId);
  }
  return {
    sql: `SELECT * FROM ${table} WHERE ${where.join(" AND ")}`,
    params
  };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const locationId = getLocationId(request);

    const tables = {};
    for (const table of TABLES) {
      const { sql, params } = buildQuery(table, tenantId, locationId);
      const r = await env.DB.prepare(sql).bind(...params).all();
      tables[table] = r.results || [];
    }

    const payload = {
      tenantId,
      locationId: locationId || null,
      exportedAt: new Date().toISOString(),
      tables
    };

    const key = `${tenantId}/backup-${Date.now()}.json`;
    await env.BACKUPS.put(key, JSON.stringify(payload), {
      httpMetadata: { contentType: "application/json" }
    });

    return json({ success: true, key });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
