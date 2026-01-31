// DELETE /api/historial/:id - Delete history entry (protected with X-Master-Key)
import { json } from "../../_lib.js";

export async function onRequestDelete(context) {
  const { request, env, params } = context;
  const { id } = params;

  // Verify X-Master-Key
  const masterKey = request.headers.get("X-Master-Key");

  if (!masterKey || masterKey !== env.MASTER_KEY) {
    return json({ success: false, error: "Unauthorized - Invalid or missing X-Master-Key" }, 401);
  }

  if (!id) {
    return json({ success: false, error: "ID is required" }, 400);
  }

  try {
    // Delete from historial table (or FIXLY_HISTORY KV)
    // Try DB first
    const result = await env.DB.prepare(`
      DELETE FROM historial WHERE id = ?
    `).bind(id).run();

    // Also try KV if exists
    if (env.FIXLY_HISTORY) {
      await env.FIXLY_HISTORY.delete(`historial_${id}`);
    }

    return json({
      success: true,
      message: `Historial entry ${id} deleted`,
      changes: result?.meta?.changes || 0
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}

// GET /api/historial/:id - Get single history entry
export async function onRequestGet(context) {
  const { request, env, params } = context;
  const { id } = params;

  // Verify X-Master-Key for read access too
  const masterKey = request.headers.get("X-Master-Key");

  if (!masterKey || masterKey !== env.MASTER_KEY) {
    return json({ success: false, error: "Unauthorized - Invalid or missing X-Master-Key" }, 401);
  }

  if (!id) {
    return json({ success: false, error: "ID is required" }, 400);
  }

  try {
    const entry = await env.DB.prepare(`
      SELECT * FROM historial WHERE id = ?
    `).bind(id).first();

    if (!entry) {
      // Try KV
      if (env.FIXLY_HISTORY) {
        const kvEntry = await env.FIXLY_HISTORY.get(`historial_${id}`, "json");
        if (kvEntry) {
          return json({ success: true, data: kvEntry });
        }
      }
      return json({ success: false, error: "Entry not found" }, 404);
    }

    return json({ success: true, data: entry });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
