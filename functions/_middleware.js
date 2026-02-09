// ==== GLOBAL CORS + ERROR HANDLER MIDDLEWARE FOR CLOUDFLARE PAGES FUNCTIONS ====

const CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Tenant-Id, X-Location-Id, X-Master-Key",
  "Access-Control-Max-Age": "86400",
  "Access-Control-Allow-Credentials": "true"
};

// Known allowed origins
const KNOWN_ORIGINS = [
  "https://admin.fixlytaller.com",
  "https://app.fixlytaller.com",
  "https://fixlytaller.com",
  "http://localhost:3000",
  "http://localhost:5173",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5173"
];

function getAllowedOrigins(env) {
  const origins = new Set(KNOWN_ORIGINS);

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

  // If origin is in allowed list
  if (origin && allowed.has(origin)) {
    return {
      ...CORS_HEADERS,
      "Access-Control-Allow-Origin": origin,
      "Vary": "Origin"
    };
  }

  // Default: allow all for MVP
  return {
    ...CORS_HEADERS,
    "Access-Control-Allow-Origin": "*"
  };
}

// Standard JSON response helper
function jsonResponse(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders
    }
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const method = request.method;
  const path = url.pathname;

  // Log incoming request
  console.log(`[MIDDLEWARE] ${method} ${path}`);

  const corsHeaders = getCorsHeaders(request, env);

  // Handle preflight OPTIONS
  if (method === "OPTIONS") {
    console.log(`[MIDDLEWARE] Preflight OK for ${path}`);
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }

  // Continue to the actual handler
  try {
    const response = await next();

    // Check for 404 (no handler found)
    if (response.status === 404) {
      // Check if it's a real 404 from our code or Pages Functions 404
      const contentType = response.headers.get("Content-Type") || "";
      if (!contentType.includes("application/json")) {
        console.log(`[MIDDLEWARE] 404 - Route not found: ${path}`);
        return jsonResponse({
          success: false,
          error: `Endpoint not found: ${method} ${path}`
        }, 404, corsHeaders);
      }
    }

    // Add CORS headers to response
    const newHeaders = new Headers(response.headers);
    for (const [key, value] of Object.entries(corsHeaders)) {
      newHeaders.set(key, value);
    }

    // Ensure Content-Type is set
    if (!newHeaders.has("Content-Type")) {
      newHeaders.set("Content-Type", "application/json");
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });
  } catch (err) {
    // Global error handler - NEVER return empty response
    console.error(`[MIDDLEWARE] Error on ${method} ${path}:`, err.message, err.stack);

    // Determine status code based on error
    let status = 500;
    if (err.message.includes("token") || err.message.includes("authorization")) {
      status = 401;
    } else if (err.message.includes("Admin") || err.message.includes("permission")) {
      status = 403;
    } else if (err.message.includes("not found")) {
      status = 404;
    } else if (err.message.includes("already exists") || err.message.includes("UNIQUE")) {
      status = 409;
    } else if (err.message.includes("required") || err.message.includes("invalid")) {
      status = 400;
    }

    return jsonResponse({
      success: false,
      error: err.message || "Internal server error"
    }, status, corsHeaders);
  }
}
