// GET /api/admin/reports/financial - Financial reports
import { json, authenticateRequest } from "../../../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true);

    const url = new URL(request.url);
    const period = url.searchParams.get("period") || "month";

    console.log(`[API] GET /api/admin/reports/financial - Period: ${period}`);

    // Get financial data
    let summary = {
      totalRevenue: 0,
      totalTransactions: 0,
      averageTransaction: 0
    };

    let revenueByPlan = {
      basic: 0,
      pro: 0,
      enterprise: 0
    };

    let recentPayments = [];

    try {
      // Get stats from pagos table
      const statsResult = await env.DB.prepare(`
        SELECT COUNT(*) as count FROM pagos WHERE status = 'approved'
      `).first();

      summary.totalTransactions = statsResult?.count || 0;

      // Get recent payments
      const paymentsResult = await env.DB.prepare(`
        SELECT * FROM pagos ORDER BY created_at DESC LIMIT 10
      `).all();

      recentPayments = paymentsResult.results || [];
    } catch (e) {
      console.log("[API] Financial data error:", e.message);
    }

    return json({
      success: true,
      data: {
        period,
        summary,
        charts: {
          revenueByPlan,
          monthlyTrend: [] // Placeholder for chart data
        },
        recentPayments
      }
    });
  } catch (err) {
    console.error("[API] GET /api/admin/reports/financial - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
