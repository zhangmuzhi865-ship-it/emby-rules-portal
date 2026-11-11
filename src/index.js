/**
 * Emby Rules Portal - Cloudflare Worker + D1
 * Multi-user (username/password) + legacy token URLs + subscriptions + IPv6 host sync (cron).
 */

const TOKEN_RE = /^[0-9a-f]{64}$/;

// Login brute-force protection (D1-backed, per-IP + per-account).
// 5 failures in 15 min from one IP, or 10 failures in 15 min for one
// account, locks that key for 15 min (429). A successful login clears both.
const RL_WINDOW_SEC = 900;
const RL_IP_MAX = 5;
const RL_USER_MAX = 10;
const RL_LOCK_SEC = 900;
const RULE_PREFIXES = ["DOMAIN-SUFFIX,", "IP-CIDR,", "IP-CIDR6,"];
const FORMAT_SPECS = [
  ["loon", "emby-direct.list", "Loon", "Loon 远程规则 · 策略 DIRECT"],
  ["surge", "emby-direct-surge.list", "Surge", "Surge 远程规则集 · DIRECT"],
  ["qx", "emby-direct-qx.list", "Quantumult X", "QX 分流引用 · direct"],
  ["clash", "emby-direct-clash.yaml", "Clash / Stash / Mihomo", "rule-provider · classical"],
];
const SUBSET_FILES = Object.fromEntries(FORMAT_SPECS.map(([slug, filename]) => [
  filename,
  [slug, slug === "clash" ? "application/yaml; charset=utf-8" : "text/plain; charset=utf-8"],
]));

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (e) {
      return textResp(500, "internal error\n");
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(syncAllIpv6(env));
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = decodeURIComponent(url.pathname);

  if (request.method === "GET" && path === "/healthz") return textResp(200, "ok\n");

  // Auth pages
  if (path === "/login" || path === "/login/") {
    if (request.method === "GET") return htmlResp(200, loginPage(""));
    if (request.method === "POST") return handleLogin(request, env);
    return textResp(405, "method not allowed\n");
  }
  if (path === "/logout" && request.method === "POST") return handleLogout(request, env);

  // Session app
  if (path === "/app" || path === "/app/") {
    const user = await getSessionUser(request, env);
    if (!user) return redirect("/login");
    if (request.method === "GET") return htmlResp(200, appPage(user));
    return textResp(405, "method not allowed\n");
  }
  if (path === "/app/api/rules" && request.method === "GET") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return jsonResp(200, await currentPayload(env, user));
  }
  if (path === "/app/api/add" && request.method === "POST") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleAdd(request, env, user);
  }
  if (path === "/app/api/delete" && request.method === "POST") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleDelete(request, env, user);
  }
  if (path === "/app/api/change-password" && request.method === "POST") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleChangePassword(request, env, user);
  }
  if (path === "/app/api/users" && request.method === "GET") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleListUsers(env, user);
  }
  if (path === "/app/api/users/create" && request.method === "POST") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleCreateUser(request, env, user);
  }
  if (path === "/app/api/users/delete" && request.method === "POST") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleDeleteUser(request, env, user);
  }
  if (path === "/app/api/users/reset-password" && request.method === "POST") {
    const user = await getSessionUser(request, env);
    if (!user) return jsonResp(401, { error: "未登录" });
    return handleResetPassword(request, env, user);
  }

  // Legacy admin token URLs: /rules-admin/<token>/...
  const adminM = path.match(/^\/rules-admin\/([0-9a-f]{64})(\/.*)?$/);
  if (adminM) {
    const token = adminM[1];
    const rest = adminM[2] || "";
    const user = await getUserByAdminToken(env, token);
    if (!user) return textResp(404, "not found\n");
    if (rest === "") return redirect(`/rules-admin/${token}/`);
    if (rest === "/" && request.method === "GET") return htmlResp(200, adminPage(user));
    if (rest === "/api/rules" && request.method === "GET") return jsonResp(200, await currentPayload(env, user));
    if (rest === "/api/add" && request.method === "POST") return handleAdd(request, env, user);
    if (rest === "/api/delete" && request.method === "POST") return handleDelete(request, env, user);
    return textResp(404, "not found\n");
  }

  // Subscription URLs: /rules-sub/<token>/<file>
  const subM = path.match(/^\/rules-sub\/([0-9a-f]{64})\/(.+)$/);
  if (subM && request.method === "GET") {
    const token = subM[1];
    const file = subM[2];
    const user = await getUserBySubToken(env, token);
    if (!user) return textResp(404, "not found\n");
    if (file === "emby-v6-host.plugin") {
      return servePlugin(user);
    }
    if (file === "emby-v6-host.sgmodule") {
      return serveSgmodule(user);
    }
    const spec = SUBSET_FILES[file];
    if (!spec) return textResp(404, "not found\n");
    const [slug, ctype] = spec;
    const rules = ruleLines(user.rules_text || "");
    return textResp(200, renderRuleset(rules, slug), ctype);
  }

  return textResp(404, "not found\n");
}

// ---------- DB helpers ----------
async function getUserByAdminToken(env, token) {
  return await env.DB.prepare("SELECT * FROM users WHERE admin_token=?").bind(token).first();
}
async function getUserBySubToken(env, token) {
  return await env.DB.prepare("SELECT * FROM users WHERE sub_token=?").bind(token).first();
}
async function getUserById(env, id) {
  return await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(id).first();
}
async function getUserByUsername(env, username) {
  return await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(username).first();
}
async function saveRules(env, userId, rulesText) {
  await env.DB.prepare("UPDATE users SET rules_text=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?")
    .bind(rulesText, userId).run();
}
async function savePlugin(env, userId, pluginText) {
  await env.DB.prepare("UPDATE users SET plugin_text=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?")
    .bind(pluginText, userId).run();
}

// ---------- Session auth ----------
function getCookie(request, name) {
  const c = request.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
async function getSessionUser(request, env) {
  const sid = getCookie(request, "er_sid");
  if (!sid) return null;
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(
    "SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token=? AND sessions.expires_at>?"
  ).bind(sid, now).first();
  if (row) row._sid = sid;
  return row || null;
}
function clientIp(request) {
  return (request.headers.get("CF-Connecting-IP") || "").trim() || "unknown";
}
async function rlGet(env, key) {
  const row = await env.DB.prepare("SELECT failures, last_attempt, locked_until FROM login_attempts WHERE key=?").bind(key).first();
  return row || { failures: 0, last_attempt: 0, locked_until: 0 };
}
// Returns remaining lock minutes (0 = not locked).
async function rlCheck(env, keys) {
  const now = Math.floor(Date.now() / 1000);
  for (const key of keys) {
    const r = await rlGet(env, key);
    if (r.locked_until > now) return Math.ceil((r.locked_until - now) / 60);
  }
  return 0;
}
// Records one failure for each key; returns true if any key just got locked.
async function rlFail(env, keys) {
  const now = Math.floor(Date.now() / 1000);
  let locked = false;
  for (const key of keys) {
    const max = key.startsWith("ip:") ? RL_IP_MAX : RL_USER_MAX;
    const r = await rlGet(env, key);
    let failures = (now - r.last_attempt > RL_WINDOW_SEC) ? 1 : r.failures + 1;
    let lockedUntil = r.locked_until > now ? r.locked_until : 0;
    if (failures >= max) { lockedUntil = now + RL_LOCK_SEC; failures = 0; locked = true; }
    await env.DB.prepare(
      "INSERT INTO login_attempts(key, failures, last_attempt, locked_until) VALUES(?,?,?,?) " +
      "ON CONFLICT(key) DO UPDATE SET failures=excluded.failures, last_attempt=excluded.last_attempt, locked_until=excluded.locked_until"
    ).bind(key, failures, now, lockedUntil).run();
  }
  return locked;
}
async function rlClear(env, keys) {
  for (const key of keys) {
    await env.DB.prepare("DELETE FROM login_attempts WHERE key=?").bind(key).run();
  }
}
async function handleLogin(request, env) {
  const fd = await request.formData();
  const username = String(fd.get("username") || "").trim().toLowerCase(); // usernames are case-insensitive (iOS autocapitalizes first letter)
  const password = String(fd.get("password") || "");
  if (!username || !password) return htmlResp(400, loginPage("请输入用户名和密码"));
  const keys = [`ip:${clientIp(request)}`, `user:${username}`];
  const lockedMin = await rlCheck(env, keys);
  if (lockedMin > 0) return htmlResp(429, loginPage(`登录尝试次数过多，请 ${lockedMin} 分钟后再试`));
  const user = await getUserByUsername(env, username);
  const ok = user && user.password_hash ? await verifyPassword(password, user.password_hash) : false;
  if (!ok) {
    const locked = await rlFail(env, keys);
    return htmlResp(locked ? 429 : 401, loginPage(locked ? "登录尝试次数过多，请 15 分钟后再试" : "用户名或密码错误"));
  }
  await rlClear(env, keys);
  const sid = randHex(32);
  const ttlDays = parseInt(env.SESSION_TTL_DAYS || "30", 10);
  const exp = Math.floor(Date.now() / 1000) + ttlDays * 86400;
  await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)").bind(sid, user.id, exp).run();
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/app",
      "Set-Cookie": `er_sid=${encodeURIComponent(sid)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttlDays * 86400}`,
      "Cache-Control": "no-store",
    },
  });
}
async function handleLogout(request, env) {
  const sid = getCookie(request, "er_sid");
  if (sid) await env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(sid).run();
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/login",
      "Set-Cookie": "er_sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
      "Cache-Control": "no-store",
    },
  });
}

async function handleChangePassword(request, env, user) {
  try {
    const fd = await request.formData();
    const oldPw = String(fd.get("old_password") || "");
    const newPw = String(fd.get("new_password") || "");
    const confirmPw = String(fd.get("confirm_password") || "");
    if (!oldPw || !newPw || !confirmPw) return jsonResp(400, { error: "请填写旧密码、新密码和确认密码" });
    if (newPw.length < 8) return jsonResp(400, { error: "新密码至少 8 位" });
    if (newPw.length > 128) return jsonResp(400, { error: "新密码过长" });
    if (newPw !== confirmPw) return jsonResp(400, { error: "两次输入的新密码不一致" });
    if (oldPw === newPw) return jsonResp(400, { error: "新密码不能与旧密码相同" });
    const fresh = await getUserById(env, user.id);
    if (!fresh || !fresh.password_hash) return jsonResp(400, { error: "当前账号未设置密码，请先联系管理员设置初始密码" });
    const ok = await verifyPassword(oldPw, fresh.password_hash);
    if (!ok) return jsonResp(401, { error: "旧密码不正确" });
    const hash = await hashPassword(newPw);
    await env.DB.prepare("UPDATE users SET password_hash=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?")
      .bind(hash, user.id).run();
    // Keep current session, invalidate other sessions.
    if (user._sid) {
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token!=?").bind(user.id, user._sid).run();
    } else {
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(user.id).run();
    }
    return jsonResp(200, { ok: true, message: "密码已更新，其他设备需重新登录" });
  } catch (e) { return errResp(e); }
}

// Password hashing: PBKDF2-SHA256, stored as pbkdf2$iter$saltHex$hashHex
// NOTE: Cloudflare Workers WebCrypto caps PBKDF2 at 100000 iterations (150000 throws NotSupportedError).
function requireOwner(user) {
  if (!user || user.role !== "owner") return jsonResp(403, { error: "需要管理员权限" });
  return null;
}
async function handleListUsers(env, user) {
  const denied = requireOwner(user); if (denied) return denied;
  const res = await env.DB.prepare("SELECT username, role, password_hash IS NOT NULL AS has_password, rules_text FROM users ORDER BY id ASC").all();
  return jsonResp(200, { users: (res.results || []).map(r => ({ username: r.username, role: r.role, has_password: !!r.has_password, rules_count: ruleLines(r.rules_text || "").length })) });
}
async function handleCreateUser(request, env, user) {
  try {
    const denied = requireOwner(user); if (denied) return denied;
    const fd = await request.formData();
    const username = String(fd.get("username") || "").trim().toLowerCase();
    const password = String(fd.get("password") || "");
    const role = String(fd.get("role") || "user") === "owner" ? "owner" : "user";
    if (!/^[a-z0-9_-]{3,32}$/.test(username)) return jsonResp(400, { error: "用户名需 3-32 位小写字母、数字、下划线或连字符" });
    if (password.length < 8) return jsonResp(400, { error: "密码至少 8 位" });
    if (password.length > 128) return jsonResp(400, { error: "密码过长" });
    const existing = await getUserByUsername(env, username);
    if (existing) return jsonResp(400, { error: "用户名已存在" });
    const hash = await hashPassword(password);
    await env.DB.prepare("INSERT INTO users(username,password_hash,role,admin_token,sub_token,ipv6_host_domain,rules_text,plugin_text) VALUES(?,?,?,?,?,?,?,NULL)").bind(username, hash, role, randHex(32), randHex(32), (env.DEFAULT_IPV6_HOST_DOMAIN || ""), "").run();
    return jsonResp(200, { ok: true, username, role });
  } catch (e) { return errResp(e); }
}
async function handleDeleteUser(request, env, user) {
  try {
    const denied = requireOwner(user); if (denied) return denied;
    const fd = await request.formData();
    const username = String(fd.get("username") || "").trim().toLowerCase();
    if (!username) return jsonResp(400, { error: "请输入用户名" });
    if (username === String(user.username || "").toLowerCase()) return jsonResp(400, { error: "不能删除自己的账号" });
    const target = await getUserByUsername(env, username);
    if (!target) return jsonResp(404, { error: "用户不存在" });
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(target.id).run();
    await env.DB.prepare("DELETE FROM users WHERE id=?").bind(target.id).run();
    return jsonResp(200, { ok: true, username });
  } catch (e) { return errResp(e); }
}
async function handleResetPassword(request, env, user) {
  try {
    const denied = requireOwner(user); if (denied) return denied;
    const fd = await request.formData();
    const username = String(fd.get("username") || "").trim().toLowerCase();
    const password = String(fd.get("password") || "");
    if (!username) return jsonResp(400, { error: "请选择用户" });
    if (password.length < 8) return jsonResp(400, { error: "密码至少 8 位" });
    if (password.length > 128) return jsonResp(400, { error: "密码过长" });
    const target = await getUserByUsername(env, username);
    if (!target) return jsonResp(404, { error: "用户不存在" });
    const hash = await hashPassword(password);
    await env.DB.prepare("UPDATE users SET password_hash=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?").bind(hash, target.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(target.id).run();
    return jsonResp(200, { ok: true, username, message: "密码已重置，该用户需重新登录" });
  } catch (e) { return errResp(e); }
}
async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return false;
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const iter = parseInt(parts[1], 10);
  const salt = hexToBuf(parts[2]);
  const expected = parts[3];
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, key, 256);
  return bufToHex(new Uint8Array(bits)) === expected;
}
async function hashPassword(password, iter = 100000) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, key, 256);
  return `pbkdf2$${iter}$${bufToHex(salt)}$${bufToHex(new Uint8Array(bits))}`;
}
function randHex(nBytes) { return bufToHex(crypto.getRandomValues(new Uint8Array(nBytes))); }
function bufToHex(buf) { return [...buf].map(b => b.toString(16).padStart(2, "0")).join(""); }
function hexToBuf(hex) { const a = new Uint8Array(hex.length/2); for(let i=0;i<a.length;i++) a[i]=parseInt(hex.substr(i*2,2),16); return a; }

// ---------- Rules logic (ported) ----------
function ruleLines(text) {
  return (text || "").split("\n").map(l => l.trim()).filter(l => RULE_PREFIXES.some(p => l.startsWith(p)));
}
function normalizeInput(raw) {
  let value = (raw || "").trim();
  if (!value) throw bad("请输入 Emby 链接或域名");
  if (value.length > 2048) throw bad("输入过长");
  const md = value.match(/https?:\/\/[^\s)>\]]+/i);
  if (md) value = md[0];
  value = value.replace(/^[\s\t\r\n[\]()<>,;]+|[\s\t\r\n[\]()<>,;]+$/g, "");
  const candidate = value.includes("://") ? value : "https://" + value;
  let host;
  try { host = new URL(candidate).hostname; } catch { throw bad("链接格式不正确"); }
  if (!host) throw bad("没有识别到域名或 IP");
  host = host.replace(/^\[|\]$/g, "");
  // IPv4/IPv6?
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const parts = host.split(".").map(Number);
    if (parts.some(p => p < 0 || p > 255)) throw bad("IP 格式不正确");
    return `IP-CIDR,${host}/32`;
  }
  if (host.includes(":")) {
    // basic IPv6 validation via URL already parsed; normalize
    return `IP-CIDR6,${host.toLowerCase()}/128`;
  }
  let domain;
  try {
    domain = new URL("https://" + host).hostname.toLowerCase().replace(/\.$/, "");
  } catch { throw bad("域名格式不正确"); }
  if (["abc","example.com","example.net","example.org"].includes(domain)) throw bad("检测到示例占位符，未添加");
  if (domain.length > 253 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain)) {
    throw bad("域名格式不正确");
  }
  return `DOMAIN-SUFFIX,${domain}`;
}
function addRule(text, rule) {
  const lines = (text || "").replace(/\n$/, "").split("\n");
  const existing = new Set(lines.map(l => l.trim()));
  if (existing.has(rule)) return { text, created: false };
  lines.push(rule);
  return { text: lines.join("\n") + "\n", created: true };
}
function deleteRule(text, rule) {
  if (typeof rule !== "string" || rule.length > 512 || rule.includes("\n") || rule.includes("\r")) throw bad("规则内容无效");
  const lines = (text || "").replace(/\n$/, "").split("\n");
  const rules = new Set(ruleLines(text));
  if (!rules.has(rule)) return { text, deleted: false };
  const updated = lines.filter(l => l.trim() !== rule);
  return { text: updated.join("\n") + "\n", deleted: true };
}

async function handleAdd(request, env, user) {
  try {
    const fd = await request.formData();
    const rule = normalizeInput(String(fd.get("url") || ""));
    const fresh = await getUserById(env, user.id);
    const res = addRule(fresh.rules_text || "", rule);
    if (res.created) await saveRules(env, user.id, res.text);
    return jsonResp(200, { created: res.created, rule });
  } catch (e) { return errResp(e); }
}
async function handleDelete(request, env, user) {
  try {
    const fd = await request.formData();
    const rule = String(fd.get("rule") || "");
    const fresh = await getUserById(env, user.id);
    const res = deleteRule(fresh.rules_text || "", rule);
    if (!res.deleted) return jsonResp(404, { error: "规则不存在，可能已被删除" });
    await saveRules(env, user.id, res.text);
    return jsonResp(200, { deleted: true, rule });
  } catch (e) { return errResp(e); }
}

// ---------- Rendering ----------
function convertRule(rule, target) {
  const idx = rule.indexOf(",");
  const kind = idx >= 0 ? rule.slice(0, idx) : rule;
  const rest = idx >= 0 ? rule.slice(idx + 1).trim() : "";
  if (target === "loon" || target === "surge") {
    if (kind === "IP-CIDR" || kind === "IP-CIDR6") return `${kind},${rest},DIRECT,no-resolve`;
    return `${kind},${rest},DIRECT`;
  }
  if (target === "qx") {
    if (kind === "DOMAIN-SUFFIX") return `host-suffix, ${rest}, direct`;
    if (kind === "IP-CIDR") return `ip-cidr, ${rest}, direct, no-resolve`;
    if (kind === "IP-CIDR6") return `ip6-cidr, ${rest}, direct, no-resolve`;
    return `host, ${rest}, direct`;
  }
  if (target === "clash") {
    if (kind === "IP-CIDR" || kind === "IP-CIDR6") return `  - ${kind},${rest},no-resolve`;
    return `  - ${kind},${rest}`;
  }
  throw bad("unsupported target");
}
function renderRuleset(rules, target) {
  if (target === "loon") {
    // Keep legacy Loon/Shadowrocket payload byte-identical: bare rules.
    return rules.length ? rules.join("\n") + "\n" : "";
  }
  const body = rules.map(r => convertRule(r, target));
  if (target === "clash") {
    return "payload:\n" + (body.length ? body.join("\n") + "\n" : "  []\n");
  }
  return body.length ? body.join("\n") + "\n" : "";
}
function renderSurgeModule(pluginText, domain) {
  if (!domain || !pluginText || !pluginText.includes("[Host]")) return null;
  const re = new RegExp(`^${escapeRe(domain)}\\s*=\\s*(\\S+)\\s*$`, "m");
  const m = pluginText.match(re);
  if (!m) return null;
  // basic IPv6 check
  if (!m[1].includes(":")) return null;
  const addr = m[1];
  return (
    "#!name=Emby IPv6 \u56fa\u5b9a Host\n" +
    "#!desc=\u4e0e Loon\u300cEmby IPv6 \u56fa\u5b9a Host\u300d\u540c\u6b3e\uff1a" +
    "\u4ec5\u56fa\u5b9a " + domain + " \u5230\u5f53\u524d IPv6\uff0c" +
    "\u4e0d\u5f3a\u5236 DIRECT \u4ee5\u5916\u7b56\u7565\u3002\n" +
    "#!system=ios\n\n" +
    "[General]\nipv6 = true\n\n" +
    "[Host]\n" + `${domain} = ${addr}\n`
  );
}
function escapeRe(s){ return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

function servePlugin(user) {
  const plugin = user.plugin_text || "";
  const domain = (user.ipv6_host_domain || "").trim().toLowerCase();
  if (!domain || !plugin.includes("[Host]") || !new RegExp(`^${escapeRe(domain)}\\s*=`, "m").test(plugin)) {
    return textResp(503, "IPv6 Host plugin is not ready\n");
  }
  return textResp(200, plugin, "text/plain; charset=utf-8");
}
function serveSgmodule(user) {
  const mod = renderSurgeModule(user.plugin_text || "", (user.ipv6_host_domain || "").trim().toLowerCase());
  if (!mod) return textResp(503, "IPv6 Host module is not ready\n");
  return textResp(200, mod, "text/plain; charset=utf-8");
}

async function currentPayload(env, user) {
  const rules = ruleLines(user.rules_text || "");
  const base = (env.PUBLIC_BASE_URL || "https://rules.example.com").replace(/\/$/, ""); // set PUBLIC_BASE_URL in wrangler.toml [vars]
  const subs = Object.fromEntries(FORMAT_SPECS.map(([slug, filename]) => [slug, `${base}/rules-sub/${user.sub_token}/${filename}`]));
  return {
    count: rules.length,
    rules,
    subscription_url: subs.loon,
    subscriptions: subs,
    formats: FORMAT_SPECS.map(([slug, _f, label, hint]) => ({ slug, label, hint, url: subs[slug] })),
  };
}

// ---------- IPv6 sync (cron) ----------
async function syncAllIpv6(env) {
  const { results } = await env.DB.prepare("SELECT id, ipv6_host_domain, plugin_text FROM users WHERE ipv6_host_domain IS NOT NULL AND ipv6_host_domain != ''").all();
  for (const u of (results || [])) {
    try { await syncOneIpv6(env, u); } catch (_) { /* keep existing on failure */ }
  }
}
async function syncOneIpv6(env, user) {
  const domain = (user.ipv6_host_domain || "").trim().toLowerCase();
  if (!domain) return;
  const addr = await resolveAAAA(domain);
  if (!addr) throw new Error("no global AAAA");
  const desired = desiredPluginText(domain, addr);
  if ((user.plugin_text || "") === desired) return;
  await savePlugin(env, user.id, desired);
}
async function resolveAAAA(domain) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=AAAA`;
  const r = await fetch(url, { headers: { "accept": "application/dns-json" } });
  if (!r.ok) throw new Error("doh failed");
  const j = await r.json();
  const vals = [];
  for (const a of (j.Answer || [])) {
    if (a.type === 28 && a.data) {
      const v = a.data.trim().toLowerCase();
      if (v.includes(":")) vals.push(v);
    }
  }
  const uniq = [...new Set(vals)].sort();
  if (uniq.length !== 1) throw new Error("expected one global AAAA");
  return uniq[0];
}
function desiredPluginText(domain, addr) {
  return (
    "#!name = Emby IPv6 固定 Host\n" +
    "#!desc = 自动同步当前 AAAA；仅固定 Host 映射，不强制 DIRECT，不使用 ipv6-preferred。\n" +
    "#!system = iOS,iPadOS\n" +
    "#!type = normal\n\n" +
    "[Host]\n" +
    `${domain} = ${addr}\n`
  );
}

// ---------- HTTP helpers ----------
function bad(msg){ const e=new Error(msg); e.status=400; return e; }
function errResp(e){ return jsonResp(e.status||500, { error: e.status ? e.message : "内部错误" }); }
function textResp(status, body, ctype="text/plain; charset=utf-8") {
  const b = typeof body === "string" ? body : String(body);
  return new Response(b, { status, headers: baseHeaders(ctype) });
}
function htmlResp(status, body) { return textResp(status, body, "text/html; charset=utf-8"); }
function jsonResp(status, obj) { return textResp(status, JSON.stringify(obj), "application/json; charset=utf-8"); }
function redirect(loc) { return new Response(null, { status: 302, headers: { Location: loc, "Cache-Control": "no-store" } }); }
function baseHeaders(ctype) {
  return {
    "Content-Type": ctype,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  };
}

// ---------- Pages ----------
function esc(s){ return String(s).replace(/[&<>"']/g, c=>({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c])); }
function loginPage(msg) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emby 规则管理 - 登录</title>
<style>body{margin:0;background:#f5f7fb;font:16px/1.5 -apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;color:#172033}
main{max-width:420px;margin:40px auto;padding:0 14px}.card{background:#fff;border:1px solid #e3e7ef;border-radius:16px;padding:22px;box-shadow:0 5px 18px rgba(16,24,40,.04)}
h1{font-size:22px;margin:0 0 14px}label{display:block;font-size:14px;color:#6c7484;margin:10px 0 4px}
input{width:100%;box-sizing:border-box;border:1px solid #cbd3e1;border-radius:12px;padding:12px;font-size:16px}
button{width:100%;margin-top:16px;border:0;border-radius:12px;background:#2563eb;color:#fff;font-size:16px;padding:13px}
.err{color:#b42318;font-size:14px;min-height:20px;margin-top:8px}</style></head><body><main><section class="card">
<h1>Emby 直连规则管理</h1><form method="post" action="/login">
<label>用户名</label><input name="username" autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false" required>
<label>密码</label><input name="password" type="password" autocomplete="current-password" required>
<button type="submit">登录</button></form><div class="err">${esc(msg||"")}</div>
</section></main></body></html>`;
}
function appPage(user) {
  const name = esc(user.username || "用户");
  return portalHtml({ title: "Emby 直连规则管理", apiBase: "/app/api", showLogout: true, who: name, isOwner: user.role === "owner" });
}
function adminPage(user) {
  return portalHtml({ title: "Emby 直连规则管理", apiBase: "./api", showLogout: false, who: "", isOwner: false });
}
function portalHtml({ title, apiBase, showLogout, who, isOwner }) {
  const logout = showLogout ? `<form method="post" action="/logout" style="margin:0"><button class="secondary" type="submit">退出登录</button></form>` : "";
  const whoLine = who ? `<div class="muted">当前用户：${esc(who)}</div>` : `<div class="muted">私密管理页 · Loon / Surge / Quantumult X / Clash · 策略 DIRECT</div>`;
  // Reuse the proven UI/behavior from legacy portal (adapted api base)
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<style>
:root{color-scheme:light;--bg:#f5f7fb;--card:#fff;--ink:#172033;--muted:#6c7484;--line:#e3e7ef;--blue:#2563eb;--green:#16803c;--red:#b42318}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","PingFang SC",sans-serif}
main{max-width:760px;margin:0 auto;padding:22px 14px 40px}.card{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px;margin:12px 0;box-shadow:0 5px 18px rgba(16,24,40,.04)}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:0 0 12px}.muted{color:var(--muted);font-size:14px}
.row{display:flex;gap:8px;align-items:center}.row input{flex:1;min-width:0}label{display:block;font-size:14px;color:var(--muted);margin:10px 0 4px}
input,select{width:100%;border:1px solid #cbd3e1;border-radius:12px;padding:13px 12px;font-size:16px;background:#fff}
button{border:0;border-radius:12px;background:var(--blue);color:#fff;font-size:16px;padding:13px 16px;white-space:nowrap;cursor:pointer}button.secondary{background:#eef3ff;color:#1d4ed8}button.delete{background:#fff0ef;color:var(--red);border:1px solid #f3bbb6;padding:8px 10px;font-size:14px}
.status{min-height:24px;margin-top:10px;font-size:14px}.ok{color:var(--green)}.err{color:var(--red)}.sub{display:block;word-break:break-all;background:#f1f4f9;border-radius:10px;padding:10px;font-size:13px;margin:8px 0}
ul{list-style:none;padding:0;margin:0;max-height:52vh;overflow:auto;border-top:1px solid var(--line)}li.rule{display:flex;gap:10px;align-items:center;padding:9px 2px;border-bottom:1px solid var(--line)}.rule-text{flex:1;min-width:0;font:13px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.undo{display:flex;gap:8px;align-items:center;margin-top:12px;padding:10px;border-radius:12px;background:#effaf2;color:#166534;font-size:14px}.undo[hidden]{display:none}.undo button{margin-left:auto;padding:8px 12px;font-size:14px}
.fmt{border-top:1px solid var(--line);padding:11px 0}.fmt:first-child{border-top:0;padding-top:2px}.fmt-head{display:flex;gap:8px;align-items:center}.fmt-name{font-size:15px;font-weight:600}.fmt-hint{color:var(--muted);font-size:12px;margin-top:1px}.fmt-head button{margin-left:auto;padding:8px 12px;font-size:14px}.fmt .sub{margin:7px 0 0}
@media (max-width:520px){.row{display:block}.row button{width:100%;margin-top:8px}main{padding-top:12px}.rule-text{font-size:12px}.undo{align-items:flex-start}}
</style>
</head>
<body>
<main>
  <section class="card" style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start"><div><h1>${esc(title)}</h1>${whoLine}</div>${logout}</section>
  <section class="card">
    <h2>添加新线路</h2>
    <form id="add-form"><div class="row"><input id="url" name="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="粘贴 https://example.com:12307/emby"><button type="submit">添加直连</button></div></form>
    <div id="status" class="status"></div><div class="muted">端口和路径会自动去除；示例占位符不会添加。</div>
  </section>
  <section class="card">
    <h2>订阅地址</h2>
    <div id="formats"><div class="muted">加载中…</div></div>
    <div class="muted" style="margin-top:10px">按你用的软件选对应那条，复制后添加为远程规则／规则集，策略选 DIRECT（QX 已内置 direct）。</div>
  </section>
  <section class="card">
    <h2>当前规则 <span id="count" class="muted"></span></h2><ul id="rules"></ul>
    <div id="undo" class="undo" hidden><span id="undo-text"></span><button id="undo-button" class="secondary" type="button">撤销</button></div>
  </section>
  ${showLogout ? `<section class="card">
    <h2>修改密码</h2>
    <form id="pw-form">
      <label>旧密码</label><input id="old_password" name="old_password" type="password" autocomplete="current-password">
      <label>新密码（至少 8 位）</label><input id="new_password" name="new_password" type="password" autocomplete="new-password">
      <label>确认新密码</label><input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password">
      <div style="margin-top:10px"><button type="submit">更新密码</button></div>
    </form>
    <div id="pw-status" class="status"></div>
    <div class="muted">更新后当前登录保持有效，其他设备会被退出。</div>
  </section>` : ``}
  ${isOwner ? `<section class="card">
    <h2>用户管理</h2>
    <ul id="users"></ul>
    <form id="user-create-form">
      <label>新建用户</label>
      <input id="new-username" name="username" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="用户名，3-32 位小写字母、数字、下划线">
      <label>初始密码（至少 8 位）</label>
      <input id="new-password" name="password" type="password" autocomplete="new-password" placeholder="初始密码">
      <label>角色</label>
      <select id="new-role" name="role"><option value="user">普通用户</option><option value="owner">管理员</option></select>
      <div style="margin-top:10px"><button type="submit">新建用户</button></div>
    </form>
    <form id="user-reset-form">
      <label>重置密码</label>
      <div class="row"><select id="reset-user" name="username"></select></div>
      <label>新密码（至少 8 位）</label>
      <input id="reset-password" name="password" type="password" autocomplete="new-password" placeholder="新密码">
      <div style="margin-top:10px"><button type="submit">重置密码</button></div>
    </form>
    <div id="user-status" class="status"></div>
    <div class="muted">新建用户初始 0 条规则，IPv6 域名与管理员相同；重置密码后该用户需重新登录。</div>
  </section>` : ``}
</main>
<script>
const API=${JSON.stringify(apiBase)};
const form=document.getElementById("add-form"),input=document.getElementById("url"),statusBox=document.getElementById("status"),formatsBox=document.getElementById("formats"),rulesBox=document.getElementById("rules"),countBox=document.getElementById("count"),undoBox=document.getElementById("undo"),undoText=document.getElementById("undo-text"),undoButton=document.getElementById("undo-button");
let lastDeleted="",undoTimer;
function showStatus(text,good){statusBox.textContent=text;statusBox.className=good?"status ok":"status err"}
function addValueFor(rule){if(rule.startsWith("DOMAIN-SUFFIX,"))return rule.slice(14);if(rule.startsWith("IP-CIDR6,"))return rule.slice(9).replace(/\\/128$/,"");if(rule.startsWith("IP-CIDR,"))return rule.slice(8).replace(/\\/32$/,"");return ""}
function hideUndo(){lastDeleted="";undoBox.hidden=true;if(undoTimer)clearTimeout(undoTimer)}
function offerUndo(rule){lastDeleted=rule;undoText.textContent="已删除此规则，可在 15 秒内撤销";undoBox.hidden=false;if(undoTimer)clearTimeout(undoTimer);undoTimer=setTimeout(hideUndo,15000)}
async function copyText(text){try{await navigator.clipboard.writeText(text);return true}catch(_){return false}}
function renderFormats(formats){formatsBox.innerHTML="";for(const fmt of (formats||[])){const wrap=document.createElement("div");wrap.className="fmt";const head=document.createElement("div");head.className="fmt-head";const info=document.createElement("div");const name=document.createElement("div");name.className="fmt-name";name.textContent=fmt.label;const hint=document.createElement("div");hint.className="fmt-hint";hint.textContent=fmt.hint;info.append(name,hint);const btn=document.createElement("button");btn.type="button";btn.className="secondary";btn.textContent="复制";btn.addEventListener("click",async()=>{const ok=await copyText(fmt.url);showStatus(ok?fmt.label+" 地址已复制":"请长按地址手动复制",ok)});head.append(info,btn);const url=document.createElement("span");url.className="sub";url.textContent=fmt.url;wrap.append(head,url);formatsBox.appendChild(wrap)}}
async function refresh(){const response=await fetch(API+"/rules",{cache:"no-store"});const data=await response.json();if(!response.ok){if(response.status===401){location.href="/login";return}throw new Error(data.error||"读取失败")}renderFormats(data.formats||[]);countBox.textContent="("+data.count+" 条)";rulesBox.innerHTML="";for(const rule of data.rules){const item=document.createElement("li");item.className="rule";const text=document.createElement("span");text.className="rule-text";text.textContent=rule;const del=document.createElement("button");del.type="button";del.className="delete";del.textContent="删除";del.addEventListener("click",()=>removeRule(rule));item.append(text,del);rulesBox.appendChild(item)}}
async function removeRule(rule){if(!confirm("确认删除这条直连规则？\\n\\n"+rule))return;showStatus("正在删除…",true);const response=await fetch(API+"/delete",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8"},body:"rule="+encodeURIComponent(rule)});const data=await response.json();if(!response.ok){showStatus(data.error||"删除失败",false);return}showStatus("已删除："+data.rule,true);offerUndo(data.rule);await refresh()}
form.addEventListener("submit",async event=>{event.preventDefault();const value=input.value.trim();if(!value)return;showStatus("正在添加…",true);const response=await fetch(API+"/add",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8"},body:"url="+encodeURIComponent(value)});const data=await response.json();if(!response.ok){showStatus(data.error||"添加失败",false);return}input.value="";hideUndo();showStatus(data.created?"已添加："+data.rule:"规则已存在："+data.rule,true);await refresh()});
undoButton.addEventListener("click",async()=>{if(!lastDeleted)return;const rule=lastDeleted,value=addValueFor(rule);if(!value){showStatus("撤销失败，请重新添加",false);hideUndo();return}const response=await fetch(API+"/add",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8"},body:"url="+encodeURIComponent(value)});const data=await response.json();if(!response.ok){showStatus(data.error||"撤销失败",false);return}hideUndo();showStatus("已恢复："+data.rule,true);await refresh()});
const pwForm=document.getElementById("pw-form"),pwStatus=document.getElementById("pw-status");
function showPwStatus(text,good){if(!pwStatus)return;pwStatus.textContent=text;pwStatus.className=good?"status ok":"status err"}
if(pwForm){pwForm.addEventListener("submit",async event=>{event.preventDefault();showPwStatus("正在更新密码…",true);const fd=new FormData(pwForm);const response=await fetch(API+"/change-password",{method:"POST",body:fd});const data=await response.json().catch(()=>({}));if(!response.ok){showPwStatus(data.error||"修改失败",false);return}pwForm.reset();showPwStatus(data.message||"密码已更新",true)})}
const usersBox=document.getElementById("users");
function showUserStatus(text,good){const el=document.getElementById("user-status");if(!el)return;el.textContent=text;el.className=good?"status ok":"status err"}
async function loadUsers(){if(!usersBox)return;const response=await fetch(API+"/users",{cache:"no-store"});const data=await response.json();if(!response.ok){showUserStatus(data.error||"读取用户失败",false);return}usersBox.innerHTML="";const resetSel=document.getElementById("reset-user");if(resetSel){resetSel.innerHTML="";for(const u of data.users){const opt=document.createElement("option");opt.value=u.username;opt.textContent=u.username;resetSel.appendChild(opt)}}for(const u of data.users){const item=document.createElement("li");item.className="rule";const text=document.createElement("span");text.className="rule-text";text.textContent=u.username+"（"+(u.role==="owner"?"管理员":"普通用户")+"）· "+u.rules_count+" 条规则 · "+(u.has_password?"已设密码":"未设密码");const del=document.createElement("button");del.type="button";del.className="delete";del.textContent="删除";del.addEventListener("click",()=>deleteUser(u.username));item.append(text,del);usersBox.appendChild(item)}}
async function deleteUser(username){if(!confirm("确认删除用户 "+username+"？该用户的规则和订阅链接将一并删除。"))return;showUserStatus("正在删除…",true);const response=await fetch(API+"/users/delete",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded;charset=UTF-8"},body:"username="+encodeURIComponent(username)});const data=await response.json();if(!response.ok){showUserStatus(data.error||"删除失败",false);return}showUserStatus("已删除用户："+username,true);await loadUsers()}
const userCreateForm=document.getElementById("user-create-form");
if(userCreateForm){userCreateForm.addEventListener("submit",async event=>{event.preventDefault();showUserStatus("正在新建用户…",true);const fd=new FormData(userCreateForm);const response=await fetch(API+"/users/create",{method:"POST",body:fd});const data=await response.json().catch(()=>({}));if(!response.ok){showUserStatus(data.error||"新建失败",false);return}userCreateForm.reset();showUserStatus("已新建用户："+data.username,true);await loadUsers()})}
const userResetForm=document.getElementById("user-reset-form");
if(userResetForm){userResetForm.addEventListener("submit",async event=>{event.preventDefault();showUserStatus("正在重置密码…",true);const fd=new FormData(userResetForm);const response=await fetch(API+"/users/reset-password",{method:"POST",body:fd});const data=await response.json().catch(()=>({}));if(!response.ok){showUserStatus(data.error||"重置失败",false);return}userResetForm.reset();showUserStatus(data.message||"密码已重置",true);await loadUsers()})}
if(usersBox){loadUsers()}
refresh().catch(()=>showStatus("读取规则失败，请刷新页面",false));
</script>
</body>
</html>`;
}
