// Create the first admin (owner) user in D1 after migrations.
// Usage:
//   node scripts/setup-admin.mjs <username> <password> [role]
//   role defaults to "owner"; use "user" for a regular user.
// The password is only used to compute a PBKDF2 hash in memory; it is never
// stored, printed, or written to disk. Tokens are generated randomly.
// Requires: wrangler logged in (`npx wrangler login`) and wrangler.toml
// configured with your database_id.
import { randomBytes, pbkdf2Sync } from "node:crypto";
import { execFileSync } from "node:child_process";

const [usernameRaw, password, roleRaw] = process.argv.slice(2);
const username = (usernameRaw || "").trim().toLowerCase();
const role = roleRaw === "user" ? "user" : "owner";

if (!/^[a-z0-9_-]{3,32}$/.test(username)) {
  console.error("username must be 3-32 chars: lowercase letters, digits, _ or -");
  process.exit(1);
}
if (!password || password.length < 8 || password.length > 128) {
  console.error("password must be 8-128 characters");
  process.exit(1);
}

const iter = 100000; // Cloudflare Workers WebCrypto PBKDF2 cap is 100000
const salt = randomBytes(16);
const key = pbkdf2Sync(password, salt, iter, 32, "sha256");
const hash = `pbkdf2$${iter}$${salt.toString("hex")}$${key.toString("hex")}`;
const adminToken = randomBytes(32).toString("hex");
const subToken = randomBytes(32).toString("hex");

// Run a D1 query via wrangler and return the parsed JSON result.
// Wrangler prints a banner line before the JSON, so extract the array.
function run(sql) {
  const out = execFileSync(
    "npx",
    ["wrangler", "d1", "execute", "DB", "--remote", "--json", "--command", sql],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const start = out.indexOf("[");
  const end = out.lastIndexOf("]");
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("unexpected wrangler output: " + out.slice(0, 200));
  }
  return JSON.parse(out.slice(start, end + 1));
}

const exists = run(`SELECT count(*) AS n FROM users WHERE username = '${username}';`)[0].results[0].n;
if (exists) {
  console.error(`user "${username}" already exists`);
  process.exit(1);
}

run(
  `INSERT INTO users (username, password_hash, role, admin_token, sub_token, ipv6_host_domain, rules_text, plugin_text) ` +
    `VALUES ('${username}', '${hash}', '${role}', '${adminToken}', '${subToken}', '', '', NULL);`,
);
console.log(`created user "${username}" (role=${role}) with 0 rules.`);
console.log("Login at <your PUBLIC_BASE_URL>/login. Keep the password safe; it cannot be recovered, only reset.");
