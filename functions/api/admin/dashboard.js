// GET /api/admin/dashboard - Admin dashboard stats
import { json, authenticateRequest } from "../../_lib.js";

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true); // requireAdmin

    console.log("[API] GET /api/admin/dashboard - Loading stats");

    // Get user stats
    let totalUsers = 0;
    let activeUsers = 0;
    let trialUsers = 0;

    try {
      const usersResult = await env.DB.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
          SUM(CASE WHEN status = 'trial' THEN 1 ELSE 0 END) as trial
        FROM users WHERE status != 'deleted'
      `).first();

      totalUsers = usersResult?.total || 0;
      activeUsers = (usersResult?.active || 0) + (usersResult?.trial || 0);
      trialUsers = usersResult?.trial || 0;
    } catch (e) {
      console.error("[API] Error getting user stats:", e.message);
    }

    // Get payment stats (from pagos table if exists)
    let totalPayments = 0;
    let monthPayments = 0;
    let pendingPayments = 0;
    let monthRevenue = 0;

    try {
      // Try to get from pagos table
      const paymentsResult = await env.DB.prepare(`
        SELECT
          COUNT(*) as total,
          SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
        FROM pagos
      `).first();

      totalPayments = paymentsResult?.total || 0;
      pendingPayments = paymentsResult?.pending || 0;
      monthPayments = paymentsResult?.approved || 0;
    } catch (e) {
      // Table might not exist, use defaults
      console.log("[API] Pagos table not found, using defaults");
    }

    // Get MercadoPago config status
    let mpEnabled = false;
    let mpWebhookConfigured = false;

    try {
      const configRow = await env.DB.prepare(
        `SELECT value FROM config WHERE key = 'mercadopago'`
      ).first();

      if (configRow?.value) {
        const mpConfig = JSON.parse(configRow.value);
        mpEnabled = mpConfig.enabled === true;
        mpWebhookConfigured = !!mpConfig.webhookUrl;
      }
    } catch (e) {
      console.log("[API] MP config not found");
    }

    // Monthly revenue calculation (mock for now, can be enhanced)
    monthRevenue = monthPayments * 5000; // Placeholder calculation

    const response = {
      success: true,
      data: {
        users: {
          total: totalUsers,
          active: activeUsers,
          trial: trialUsers,
          growth: "+12%" // Placeholder
        },
        payments: {
          total: totalPayments,
          month: monthPayments,
          pending: pendingPayments,
          growth: "+8%" // Placeholder
        },
        revenue: {
          month: monthRevenue,
          formatted: `$${monthRevenue.toLocaleString()}`
        },
        mercadopago: {
          enabled: mpEnabled,
          webhookConfigured: mpWebhookConfigured,
          status: mpEnabled ? "active" : "inactive"
        }
      }
    };

    console.log("[API] GET /api/admin/dashboard - Success");
    return json(response);
  } catch (err) {
    console.error("[API] GET /api/admin/dashboard - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
