// ==== GLOBAL CORS MIDDLEWARE FOR CLOUDFLARE PAGES FUNCTIONS ====

const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Tenant-Id, X-Location-Id, X-Master-Key",
  "Access-Control-Max-Age": "86400"
};

function getAllowedOrigins(env) {
  const origins = new Set();

  // Add configured domains
  if (env?.ADMIN_DOMAIN) origins.add(env.ADMIN_DOMAIN.trim());
  if (env?.APP_DOMAIN) origins.add(env.APP_DOMAIN.trim());

  // Add from CORS_ALLOWED comma-separated list
  if (env?.CORS_ALLOWED) {
    env.CORS_ALLOWED.split(",").forEach(o => {
      const v = (o || "").trim();
      if (v) origins.add(v);
    });
  }

  return origins;
}

function getCorsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = getAllowedOrigins(env);

  // If no origins configured, allow all (MVP mode)
  if (allowed.size === 0) {
    return {
      ...CORS_HEADERS,
      "Access-Control-Allow-Origin": "*"
    };
  }

  // If origin is in allowed list
  if (origin && allowed.has(origin)) {
    return {
      ...CORS_HEADERS,
      "Access-Control-Allow-Origin": origin,
      "Vary": "Origin"
    };
  }

  // Default: allow all for MVP (change to empty string for strict mode)
  return {
    ...CORS_HEADERS,
    "Access-Control-Allow-Origin": "*"
  };
}

export async function onRequest(context) {
  const { request, env, next } = context;

  // Handle preflight OPTIONS
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: getCorsHeaders(request, env)
    });
  }

  // Continue to the actual handler
  try {
    const response = await next();

    // Add CORS headers to response
    const corsHeaders = getCorsHeaders(request, env);
    const newHeaders = new Headers(response.headers);

    for (const [key, value] of Object.entries(corsHeaders)) {
      newHeaders.set(key, value);
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  } catch (err) {
    // Return error with CORS headers
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        ...getCorsHeaders(request, env)
      }
    });
  }
}
