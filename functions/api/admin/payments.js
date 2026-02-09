// GET /api/admin/payments - Admin payments list
import { json, authenticateRequest } from "../../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true);

    console.log("[API] GET /api/admin/payments - Loading payments");

    let payments = [];
    let statistics = {
      totalPayments: 0,
      totalAmount: 0,
      pendingPayments: 0,
      approvedPayments: 0
    };

    try {
      // Get payments from pagos table
      const result = await env.DB.prepare(`
        SELECT * FROM pagos ORDER BY created_at DESC LIMIT 100
      `).all();

      payments = result.results || [];

      // Calculate statistics
      const statsResult = await env.DB.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
        FROM pagos
      `).first();

      statistics = {
        totalPayments: statsResult?.total || 0,
        totalAmount: 0, // Would need amount column
        pendingPayments: statsResult?.pending || 0,
        approvedPayments: statsResult?.approved || 0
      };
    } catch (e) {
      console.log("[API] Pagos table error:", e.message);
      // Return empty but valid response
    }

    return json({
      success: true,
      data: {
        payments,
        statistics
      }
    });
  } catch (err) {
    console.error("[API] GET /api/admin/payments - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
