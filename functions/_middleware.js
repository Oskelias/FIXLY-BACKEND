// ==== GLOBAL CORS MIDDLEWARE FOR CLOUDFLARE PAGES FUNCTIONS ====

// Fixed CORS headers
const CORS_METHODS = "GET, POST, PUT, DELETE, PATCH, OPTIONS";
const CORS_HEADERS_ALLOWED = "Content-Type, Authorization, X-Tenant-Id, X-Location-Id, X-Master-Key";
const CORS_MAX_AGE = "86400";

// Allowed origins - ALWAYS allow these
const ALLOWED_ORIGINS = [
  "https://admin.fixlytaller.com",
  "https://app.fixlytaller.com",
  "https://fixlytaller.com",
  "http://localhost:3000",
  "http://localhost:5173",
  "http://localhost:8080",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:8080"
];

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "";

  // Check if origin is allowed
  const isAllowed = ALLOWED_ORIGINS.includes(origin) || origin.endsWith(".fixlytaller.com");

  // IMPORTANT: When using credentials, we CANNOT use "*"
  // We must echo back the specific origin
  const allowOrigin = isAllowed ? origin : ALLOWED_ORIGINS[0];

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": CORS_METHODS,
    "Access-Control-Allow-Headers": CORS_HEADERS_ALLOWED,
    "Access-Control-Max-Age": CORS_MAX_AGE,
    "Vary": "Origin"
  };
}

// Helper to create JSON response with CORS
function corsJson(data, status, request) {
  const headers = {
    "Content-Type": "application/json",
    ...getCorsHeaders(request)
  };

  return new Response(JSON.stringify(data), { status, headers });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const method = request.method;
  const url = new URL(request.url);
  const path = url.pathname;

  // Get CORS headers for this request
  const corsHeaders = getCorsHeaders(request);

  // ALWAYS handle OPTIONS preflight first
  if (method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }

  try {
    // Call the actual handler
    const response = await next();

    // Clone response and add CORS headers
    const newHeaders = new Headers(response.headers);

    // Add ALL CORS headers
    Object.entries(corsHeaders).forEach(([key, value]) => {
      newHeaders.set(key, value);
    });

    // Ensure Content-Type
    if (!newHeaders.has("Content-Type")) {
      newHeaders.set("Content-Type", "application/json");
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders
    });

  } catch (err) {
    // Error handler - ALWAYS return JSON with CORS headers
    console.error(`[CORS-MW] Error: ${method} ${path}`, err.message);

    let status = 500;
    const msg = err.message || "";

    if (msg.includes("token") || msg.includes("authorization") || msg.includes("No authorization")) {
      status = 401;
    } else if (msg.includes("Admin") || msg.includes("permission")) {
      status = 403;
    } else if (msg.includes("not found")) {
      status = 404;
    }

    return corsJson({
      success: false,
      error: err.message || "Internal server error"
    }, status, request);
  }
}
