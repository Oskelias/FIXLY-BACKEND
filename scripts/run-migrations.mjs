#!/usr/bin/env node
import { execSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const dbName = process.env.D1_DB_NAME || "fixly-taller-db";
const remoteFlag = process.argv.includes("--remote") ? "--remote" : "";

const files = readdirSync("migrations")
  .filter((f) => f.endsWith(".sql"))
  .sort();

for (const file of files) {
  const sql = readFileSync(join("migrations", file), "utf8");
  const escaped = sql.replace(/"/g, '\\"').replace(/\n/g, " ");
  const cmd = `npx wrangler d1 execute ${dbName} ${remoteFlag} --command "${escaped}"`;
  console.log(`Applying ${file}...`);
  execSync(cmd, { stdio: "inherit" });
}

console.log("Migrations completed.");
