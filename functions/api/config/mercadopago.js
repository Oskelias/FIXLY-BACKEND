// GET/POST /api/config/mercadopago - MercadoPago configuration
import { json, authenticateRequest, nowISO } from "../../_lib.js";

// Default config structure
const DEFAULT_CONFIG = {
  enabled: false,
  publicKey: "",
  accessToken: "",
  webhookUrl: "",
  sandboxMode: true
};

export async function onRequestGet(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true);

    console.log("[API] GET /api/config/mercadopago - Fetching config");

    // Try to get from D1 first
    let config = null;

    try {
      // Ensure table exists
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS config (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT
        )
      `).run();

      const row = await env.DB.prepare(
        `SELECT value FROM config WHERE key = 'mercadopago'`
      ).first();

      if (row?.value) {
        config = JSON.parse(row.value);
      }
    } catch (dbErr) {
      console.error("[API] GET /api/config/mercadopago - DB error:", dbErr.message);
    }

    // Try KV fallback if no D1 config
    if (!config && env.FIXLY_KV) {
      try {
        const kvConfig = await env.FIXLY_KV.get("config:mercadopago", "json");
        if (kvConfig) {
          config = kvConfig;
        }
      } catch (kvErr) {
        console.error("[API] GET /api/config/mercadopago - KV error:", kvErr.message);
      }
    }

    // Use defaults if no config found
    const finalConfig = {
      ...DEFAULT_CONFIG,
      ...(config || {}),
      // Never expose full access token in GET response
      accessToken: config?.accessToken ? "***configured***" : ""
    };

    console.log("[API] GET /api/config/mercadopago - Config loaded:", {
      enabled: finalConfig.enabled,
      hasPublicKey: !!finalConfig.publicKey,
      hasAccessToken: !!config?.accessToken
    });

    return json({
      success: true,
      data: finalConfig
    });
  } catch (err) {
    console.error("[API] GET /api/config/mercadopago - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    await authenticateRequest(request, env, true);

    const body = await request.json();
    const { enabled, publicKey, accessToken, webhookUrl, sandboxMode } = body;

    console.log("[API] POST /api/config/mercadopago - Saving config:", {
      enabled,
      hasPublicKey: !!publicKey,
      hasAccessToken: !!accessToken,
      webhookUrl,
      sandboxMode
    });

    // Build config object
    const config = {
      enabled: enabled === true,
      publicKey: publicKey || "",
      accessToken: accessToken || "",
      webhookUrl: webhookUrl || "",
      sandboxMode: sandboxMode !== false, // default true
      updatedAt: nowISO()
    };

    // Save to D1
    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS config (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          updated_at TEXT
        )
      `).run();

      await env.DB.prepare(`
        INSERT INTO config (key, value, updated_at)
        VALUES ('mercadopago', ?, datetime('now'))
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
      `).bind(JSON.stringify(config)).run();

      console.log("[API] POST /api/config/mercadopago - Saved to D1");
    } catch (dbErr) {
      console.error("[API] POST /api/config/mercadopago - D1 save error:", dbErr.message);
    }

    // Also save to KV for redundancy
    if (env.FIXLY_KV) {
      try {
        await env.FIXLY_KV.put("config:mercadopago", JSON.stringify(config));
        console.log("[API] POST /api/config/mercadopago - Saved to KV");
      } catch (kvErr) {
        console.error("[API] POST /api/config/mercadopago - KV save error:", kvErr.message);
      }
    }

    return json({
      success: true,
      data: {
        ...config,
        accessToken: config.accessToken ? "***configured***" : ""
      }
    });
  } catch (err) {
    console.error("[API] POST /api/config/mercadopago - Error:", err.message);
    const status = err.message.includes("Admin") ? 403 :
                   err.message.includes("token") ? 401 : 500;
    return json({ success: false, error: err.message }, status);
  }
}
