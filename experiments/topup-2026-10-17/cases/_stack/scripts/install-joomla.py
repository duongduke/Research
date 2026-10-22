#!/usr/bin/env python3
"""Install Joomla! 4.2.x through the stock web installer (lab only).

Runs against a base URL that reaches the Joomla docroot over loopback
(SSH local forwarding on the lab VM: 127.0.0.1:18920 -> 8920 for 4.2.7,
127.0.0.1:18921 -> 8921 for 4.2.8).

Flow mirrors installation/template/js/{setup,template}.js:
  GET  /installation/index.php                      -> session cookie + CSRF token
  POST ?task=installation.dbcheck&format=json       -> session stores setup.options
  POST ?task=installation.{create,populate1,populate2,populate3,custom1,custom2,config}
Each response returns a refreshed token (Joomla.replaceTokens).

Every request/response is appended to the log file given by --log so the
installation is auditable. No request here is part of the CVE reproduction.
"""
import argparse
import json
import re
import sys

import requests

TOKEN_RE = re.compile(r'name="([0-9a-f]{32})" value="1"')


def log(fh, title, resp):
    body = resp.text
    fh.write(f"\n===== {title} =====\n")
    fh.write(f"{resp.request.method} {resp.request.url}\n")
    fh.write(f"--> {resp.status_code} {resp.headers.get('Content-Type','')} ({len(body)} bytes)\n")
    fh.write(body[:4000] + ("\n...[truncated]\n" if len(body) > 4000 else "\n"))
    fh.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--db-user", required=True)
    ap.add_argument("--db-pass", required=True)
    ap.add_argument("--db-name", required=True)
    ap.add_argument("--site-name", required=True)
    ap.add_argument("--admin-pass", default="<lab-admin-pass>")
    ap.add_argument("--log", required=True)
    a = ap.parse_args()

    s = requests.Session()
    with open(a.log, "w") as fh:
        r = s.get(a.base + "/installation/index.php", timeout=30)
        log(fh, "GET installer", r)
        m = TOKEN_RE.search(r.text)
        if not m:
            print("no token found", file=sys.stderr)
            return 2
        token = m.group(1)

        data = {
            f"jform[language]": "en-GB",
            f"jform[site_name]": a.site_name,
            "jform[admin_email]": "admin@example.test",
            "jform[admin_user]": "labadmin",
            "jform[admin_username]": "labadmin",
            "jform[admin_password]": a.admin_pass,
            "jform[db_type]": "mysqli",
            "jform[db_host]": "db",
            "jform[db_user]": a.db_user,
            "jform[db_pass]": a.db_pass,
            "jform[db_name]": a.db_name,
            "jform[db_prefix]": "jos_",
            "jform[db_old]": "backup",
            "jform[db_encryption]": "0",
            "jform[db_sslverifyservercert]": "0",
            "jform[db_sslkey]": "",
            "jform[db_sslcert]": "",
            "jform[db_sslca]": "",
            "jform[db_sslcipher]": "",
            token: "1",
        }

        def post(task, payload):
            nonlocal token
            # refresh CSRF field name from the previous response's token
            payload = {k: v for k, v in payload.items() if not re.fullmatch(r"[0-9a-f]{32}", k)}
            payload[token] = "1"
            resp = s.post(f"{a.base}/installation/index.php?task=installation.{task}&format=json",
                          data=payload, timeout=180)
            log(fh, f"POST installation.{task}", resp)
            try:
                j = resp.json()
            except Exception:
                print(f"{task}: non-JSON response", file=sys.stderr)
                return None
            if j.get("token"):
                token = j["token"]
            if j.get("error"):
                print(f"{task}: ERROR {j.get('message')}", file=sys.stderr)
            return j

        j = post("dbcheck", data)
        if not j or not j.get("data", {}).get("validated"):
            print("dbcheck failed", file=sys.stderr)
            return 3
        for task in ["create", "populate1", "populate2", "populate3", "custom1", "custom2", "config"]:
            j = post(task, data)
            if j is None or j.get("error"):
                print(f"install step failed: {task}", file=sys.stderr)
                return 4
        print("installer steps complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
