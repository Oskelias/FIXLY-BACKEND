// POST /api/backups/restore - Restore tenant data from R2 backup
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

function buildDelete(table, tenantId, locationId) {
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
  return { sql: `DELETE FROM ${table} WHERE ${where.join(" AND ")}`, params };
}

function buildInsert(table, row) {
  const keys = Object.keys(row);
  const placeholders = keys.map(() => "?").join(", ");
  return {
    sql: `INSERT INTO ${table} (${keys.join(", ")}) VALUES (${placeholders})`,
    params: keys.map(k => row[k])
  };
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const user = await authenticateRequest(request, env);
    const tenantId = user.tenantId;
    const body = await request.json();
    const locationId = getLocationId(request, body);

    if (!body.key) {
      return json({ success: false, error: "Backup key is required" }, 400);
    }

    const obj = await env.BACKUPS.get(body.key);
    if (!obj) {
      return json({ success: false, error: "Backup not found" }, 404);
    }

    const payload = JSON.parse(await obj.text());
    if (payload.tenantId !== tenantId) {
      return json({ success: false, error: "Backup tenant mismatch" }, 403);
    }

    const restoreLocationId = locationId || payload.locationId || null;

    for (const table of TABLES) {
      const { sql, params } = buildDelete(table, tenantId, restoreLocationId);
      await env.DB.prepare(sql).bind(...params).run();
    }

    for (const table of TABLES) {
      const rows = payload.tables?.[table] || [];
      for (const row of rows) {
        const { sql, params } = buildInsert(table, row);
        await env.DB.prepare(sql).bind(...params).run();
      }
    }

    return json({ success: true, restored: true });
  } catch (err) {
    return json({ success: false, error: err.message }, 401);
  }
}
