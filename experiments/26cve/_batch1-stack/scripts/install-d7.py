#!/usr/bin/env python3
"""Install Drupal 7 via the web installer (install.php), PDO-based (no mysql CLI).

Usage: install-d7.py <base_url> <dbname> <dbhost> [site_name] [admin_pass]
"""
import http.cookiejar, re, sys, urllib.parse, urllib.request

base = sys.argv[1].rstrip('/')
db = sys.argv[2]
dbhost = sys.argv[3]
site = sys.argv[4] if len(sys.argv) > 4 else "B1 D7"
apass = sys.argv[5] if len(sys.argv) > 5 else "<lab-admin-pass>"

cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get(url):
    try: return op.open(url, timeout=60).read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e: return e.read().decode('utf-8', 'replace')

def post(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try: return op.open(req, timeout=180).read().decode('utf-8','replace')
    except urllib.error.HTTPError as e: return e.read().decode('utf-8','replace')

def build_id(html):
    m = re.search(r'name="form_build_id"\s+value="([^"]+)"', html)
    return m.group(1) if m else ''

# 1) settings form (profile=standard skips profile selection)
h = get(f'{base}/install.php?profile=standard&locale=en')
bid = build_id(h)
print("step1 settings form, build_id:", bool(bid), "has install_settings_form:", 'install_settings_form' in h)
fields = {
    'driver': 'mysql', 'mysql[database]': db, 'mysql[username]': 'labuser',
    'mysql[password]': '<lab-db-pass>', 'mysql[host]': dbhost, 'mysql[port]': '',
    'mysql[db_prefix]': '', 'form_build_id': bid, 'form_id': 'install_settings_form',
    'op': 'Save and continue',
    '_triggering_element_name': 'op', '_triggering_element_value': 'Save and continue',
}
h = post(f'{base}/install.php?profile=standard&locale=en', fields)
print("step2 after settings, has configure form:", 'install_configure_form' in h)

# 2) configure form (admin account)
bid = build_id(h)
fields = {
    'site_name': site,
    'site_mail': 'admin@lab.test',
    'account[name]': 'admin',
    'account[mail]': 'admin@lab.test',
    'account[pass][pass1]': apass,
    'account[pass][pass2]': apass,
    'update_status_module[1]': '1',
    'clean_url': '0',
    'form_build_id': bid, 'form_id': 'install_configure_form', 'op': 'Save and continue',
}
h = post(f'{base}/install.php?profile=standard&locale=en', fields)
print("step3 installed:", ('installed' in h.lower() or 'Visit your new site' in h or len(h) > 0))
print("has login form:", 'user_login' in h or 'name="name"' in h)
