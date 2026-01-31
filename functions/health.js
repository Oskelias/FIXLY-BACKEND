// GET /health - Health check endpoint
import { json, nowISO } from "./_lib.js";

export async function onRequestGet() {
  return json({
    status: "ok",
    version: "2.0.0-pages",
    timestamp: nowISO(),
    endpoints: [
      "GET  /health",
      "GET  /auth/me",
      "POST /auth/login",
      "POST /auth/logout",
      "POST /auth/public/login",
      "POST /api/auth/login",
      "POST /api/auth/logout",
      "GET  /api/admin/users",
      "POST /api/admin/users",
      "PUT  /api/admin/user/:username",
      "DELETE /api/admin/user/:username",
      "PUT  /api/admin/user/:username/pause",
      "GET  /api/app/dashboard",
      "GET  /api/app/reparaciones",
      "POST /api/app/reparaciones",
      "PUT  /api/app/reparaciones/:id",
      "DELETE /api/app/reparaciones/:id",
      "GET  /api/app/clientes",
      "POST /api/app/clientes",
      "GET  /api/app/pedidos",
      "POST /api/app/pedidos",
      "GET  /api/devices",
      "POST /api/devices/revoke",
      "GET  /api/historial/:id",
      "DELETE /api/historial/:id"
    ]
  });
}
