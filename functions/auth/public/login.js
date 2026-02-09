// POST /auth/public/login - Public login endpoint
import { json, verifyPassword, generateJWT, manageDeviceSessions, nowISO } from "../../_lib.js";

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const { username, password } = await request.json();

    if (!username || !password) {
      return json({ success: false, error: "Username and password are required" }, 400);
    }

    // Find user
    const user = await env.DB.prepare(`
      SELECT * FROM users WHERE username = ? AND status != 'deleted'
    `).bind(username).first();

    if (!user) {
      return json({ success: false, error: "Invalid credentials" }, 401);
    }

    // Verify password
    const ok = await verifyPassword(password, user.password);
    if (!ok) {
      return json({ success: false, error: "Invalid credentials" }, 401);
    }

    // Check account status
    if (user.status === "paused") {
      return json({ success: false, error: "Account is paused" }, 403);
    }

    // Check trial expiration
    if (user.status === "trial" && user.trial_ends_at) {
      if (new Date(user.trial_ends_at) < new Date()) {
        await env.DB.prepare(`UPDATE users SET status = ? WHERE id = ?`).bind("expired", user.id).run();
        return json({ success: false, error: "Trial period has expired" }, 403);
      }
    }

    // Generate JWT
    const deviceId = crypto.randomUUID();
    const payload = {
      userId: user.id,
      username: user.username,
      tenantId: user.tenant_id,
      role: user.role,
      plan: user.plan,
      deviceId,
      exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60 // 24 hours
    };

    const token = await generateJWT(payload, env.JWT_SECRET);

    // Manage device sessions
    await manageDeviceSessions(user, env, token, deviceId, {
      deviceName: request.headers.get("X-Device-Name") || "",
      ip: request.headers.get("CF-Connecting-IP") || "",
      ua: request.headers.get("User-Agent") || ""
    });

    // Update last login
    await env.DB.prepare(`UPDATE users SET last_login = datetime(?) WHERE id = ?`).bind(nowISO(), user.id).run();

    return json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username || "",
        tenantId: user.tenant_id || "",
        role: user.role || "",
        plan: user.plan || "",
        status: user.status || "",
        redirectUrl: user.role === "admin" ? "/admin" : "/app"
      }
    });
  } catch (err) {
    return json({ success: false, error: err.message }, 500);
  }
}
