import worker from "../index.js";

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" }
  });
}

export default {
  async fetch(request: Request, env: Record<string, unknown>, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/health" && request.method === "GET") {
      return jsonResponse({ ok: true });
    }

    if (path === "/auth/public/register" && request.method === "POST") {
      let payload: Record<string, unknown> | null = null;

      try {
        payload = await request.json();
      } catch {
        return jsonResponse({ ok: false, message: "Invalid JSON body" }, 400);
      }

      const requiredFields = [
        "tallerNombre",
        "ownerNombre",
        "email",
        "telefono",
        "localidad",
        "pais"
      ];

      const missing = requiredFields.filter(
        (field) => !payload || payload[field] === undefined || payload[field] === null || payload[field] === ""
      );

      if (missing.length > 0) {
        return jsonResponse(
          { ok: false, message: `Missing fields: ${missing.join(", ")}` },
          400
        );
      }

      return jsonResponse({ ok: true, message: "Register endpoint active" });
    }

    return worker.fetch(request, env, ctx);
  }
};
