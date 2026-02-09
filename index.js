// ==== FIX-CORS HELPERS (normalized) ====
function __normOrigin(v) {
  return (v || "").trim().replace(/\/+$/, ""); // saca "/" final
}

function __fix_allowedOrigins(env) {
  const set = new Set();

  const add = (v) => {
    const n = __normOrigin(v);
    if (n) set.add(n);
  };

  add(env?.ADMIN_DOMAIN);
  add(env?.APP_DOMAIN);

  if (env && typeof env.CORS_ALLOWED === "string") {
    env.CORS_ALLOWED.split(",").forEach(add);
  }

  return set;
}

function __fix_withCORS(resp, request, env) {
  try {
    const origin = __normOrigin(request.headers.get("Origin"));
    const allow = __fix_allowedOrigins(env);

    const h = new Headers(resp.headers);

    if (origin && allow.has(origin)) {
      h.set("Access-Control-Allow-Origin", origin);
      h.set("Vary", "Origin");
      h.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS");
      h.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-Id");
      // h.set("Access-Control-Allow-Credentials", "true"); // solo si usás cookies
    }

    return new Response(resp.body, { status: resp.status, headers: h });
  } catch {
    return resp;
  }
}

function __fix_handlePreflight(request, env) {
  const origin = __normOrigin(request.headers.get("Origin"));
  const allow = __fix_allowedOrigins(env);

  const headers = {
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,PATCH,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Tenant-Id",
  };

  if (origin && allow.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
    // headers["Access-Control-Allow-Credentials"] = "true"; // si cookies
  }

  return new Response(null, { status: 204, headers });
}
// ==== /FIX-CORS HELPERS ====
