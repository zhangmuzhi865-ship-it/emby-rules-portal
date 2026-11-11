#!/usr/bin/env python3
"""External replacement for the Worker cron (use when your Cloudflare account
is already at the Free-plan limit of 5 cron triggers, so the Worker's */5
IPv6 sync cannot be set).

Replicates the Worker logic: for every D1 user with an ipv6_host_domain,
resolve its single global AAAA via DoH and store the desired plugin text
when it differs. Only writes on change.

Environment:
  CLOUDFLARE_API_TOKEN   API token with D1:Edit on this database
  CLOUDFLARE_ACCOUNT_ID  Cloudflare account ID
  D1_DATABASE_ID          D1 database ID (from wrangler.toml)
Run every 5 minutes, e.g. a systemd timer or cron. The token is only read
from the environment; it is never printed or stored by this script.
"""
import json, re, sys, os, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta

BJ = timezone(timedelta(hours=8))

def log(msg):
    print(datetime.now(BJ).strftime("%Y-%m-%d %H:%M:%S") + " " + msg, flush=True)

def d1_query(sql, params=None):
    token = os.environ["CLOUDFLARE_API_TOKEN"]
    account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
    dbid = os.environ["D1_DATABASE_ID"]
    body = json.dumps({"sql": sql, "params": params or []}).encode()
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{dbid}/query",
        data=body, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"D1 API http={e.code} {e.read().decode(errors='ignore')[:200]}")
    if not data.get("success"):
        raise RuntimeError(f"D1 API success=false errors={data.get('errors')}")
    return data["result"][0]["results"]

def doh_aaaa(domain):
    req = urllib.request.Request(
        f"https://cloudflare-dns.com/dns-query?name={domain}&type=AAAA",
        headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        j = json.loads(r.read().decode())
    vals = sorted({a["data"].strip().lower() for a in (j.get("Answer") or [])
                   if a.get("type") == 28 and a.get("data") and ":" in a["data"]})
    if len(vals) != 1:
        raise RuntimeError(f"{domain}: expected one global AAAA, got {vals}")
    return vals[0]

def desired_plugin(domain, addr):
    return ("#!name = Emby IPv6 固定 Host\n"
            "#!desc = 自动同步当前 AAAA；仅固定 Host 映射，不强制 DIRECT，不使用 ipv6-preferred。\n"
            "#!system = iOS,iPadOS\n"
            "#!type = normal\n\n"
            "[Host]\n"
            f"{domain} = {addr}\n")

def main():
    users = d1_query("SELECT id, username, ipv6_host_domain, plugin_text FROM users "
                     "WHERE ipv6_host_domain IS NOT NULL AND ipv6_host_domain != ''")
    changed = 0
    for u in users:
        domain = (u["ipv6_host_domain"] or "").strip().lower()
        if not domain:
            continue
        try:
            addr = doh_aaaa(domain)
        except Exception as e:
            log(f"{u['username']}: skip, resolve failed: {e}")
            continue
        want = desired_plugin(domain, addr)
        if (u["plugin_text"] or "") == want:
            log(f"{u['username']}: up to date ({addr})")
            continue
        d1_query("UPDATE users SET plugin_text=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?",
                 [want, u["id"]])
        log(f"{u['username']}: plugin updated to {addr}")
        changed += 1
    log(f"done, {changed} user(s) updated")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"ERROR: {e}")
        sys.exit(1)
