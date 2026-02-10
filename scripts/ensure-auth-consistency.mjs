#!/usr/bin/env node
import { execSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";

const dbName = process.env.D1_DB_NAME || "fixly-taller-db";
const remoteFlag = process.argv.includes("--remote") ? "--remote" : "";

function runSql(sql) {
  const escaped = sql.replace(/"/g, '\\"').replace(/\n/g, " ");
  const cmd = `npx wrangler d1 execute ${dbName} ${remoteFlag} --command "${escaped}"`;
  return execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

const adminUsername = "admin";
const adminPassword = "Admin628";
const adminRole = "admin";
const adminStatus = "active";
const adminPasswordHash = sha256Hex(adminPassword);

console.log(`Checking users.password format in D1 (${dbName})...`);
const invalidCheck = runSql(`
  SELECT COUNT(*) AS invalid_password_rows
  FROM users
  WHERE password IS NULL
     OR TRIM(password) = ''
     OR NOT (TRIM(password) GLOB '[0-9A-Fa-f]*' AND LENGTH(TRIM(password)) = 64);
`);
console.log(invalidCheck.trim());

console.log("Checking if admin user exists...");
const adminCheck = runSql(`SELECT id, tenant_id, username, role, status FROM users WHERE username = '${adminUsername}' LIMIT 1;`);
console.log(adminCheck.trim());

if (!/"username"\s*:\s*"admin"/.test(adminCheck)) {
  console.log("Admin user not found. Creating tenant and admin user...");

  runSql(`
    INSERT INTO tenants (id, nombre, status, plan, created_at)
    SELECT 'system-tenant', 'Fixly System', 'active', 'free', datetime('now')
    WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE id = 'system-tenant');
  `);

  runSql(`
    INSERT INTO users (id, tenant_id, username, password, role, status, email, created_at)
    VALUES (
      '${randomUUID()}',
      'system-tenant',
      '${adminUsername}',
      '${adminPasswordHash}',
      '${adminRole}',
      '${adminStatus}',
      'admin@fixlytaller.com',
      datetime('now')
    );
  `);

  console.log("Admin user created successfully.");
} else {
  console.log("Admin user already exists. No create needed.");
}

console.log("Done.");
