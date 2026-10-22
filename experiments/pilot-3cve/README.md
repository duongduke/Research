# Pilot 3-CVE lab — deployment & release verification

> Date: 2026-10-07. Lab VM: `<lab-user>@<lab-ip>` (Ubuntu 24.04.5 LTS, Docker 29.8.2).
> Scope of this step: **verify releases are downloadable + runnable, build the required
> configuration states, record exact versions/digests** — *no PoC / no exploitation*.
> All containers are bound to **127.0.0.1 only**. No CGI, no RCE payloads.
>
> Status: **deployment verified.** Config states A(i)/A(ii), B(i)/B(ii)/B(iii) built and
> exerciseable. One dependency gap found (JSON:API not core in Drupal 8.6 — see §4).

## 1. Release verification table

| Case | Vulnerable build (source) | sha256 / digest | Fixed build | Download / run | Config states built |
|---|---|---|---|---|---|
| **A** CVE-2024-10924 | Really Simple Security **9.1.1.1** (downloads.wordpress.org/plugin/really-simple-ssl.9.1.1.1.zip) on WordPress **6.7.1** (`wordpress:6.7.1-apache`) | plugin `c61c21ba0d63ee9f3eeda891e6e7c5758925875a3be729717c77d42acbfdc994`; image `sha256:43693c77589bcad6f6babe86fa14728a19224445ff883c4dbf8660d260dd547b` | plugin **9.1.2** (`d972aa17…5f7e`) | ✅ both zips 200 (~1.38 MB); both plugin versions active | 2FA **ON** / 2FA **OFF** (wp-cli `rsssl_options.login_protection_enabled`) on both versions |
| **B** CVE-2019-6340 | Drupal **8.6.9** (`drupal:8.6.9-apache`) | image `sha256:d6073e2f6c662a9406cbe0b00215276ca206ded5e170268a29faa104bf2b97f0` | Drupal **8.6.10** (`drupal:8.6.10-apache`) | ✅ both official tags exist & pulled; site installed (Drush 9.7.3) | (i) REST on; (ii) REST off + JSON:API on*; (iii) both off |
| **C** CVE-2020-12625 | Roundcube **1.4.3** (`roundcube/roundcubemail:1.4.3-apache`) | image `sha256:0ee2f1b7a008b719ec8e0a36020e9a4e773acc5ca9dde787742e180d7c78628c` | Roundcube **1.4.4** (`…:1.4.4-apache`) | ✅ both tags exist & pulled; DB schema created; IMAP login works | mailbox backend (IMAP/SMTP) + seeded message; login functional |
| — | MariaDB **10.11** (`mariadb:10.11`) | image `sha256:7db29378d4fdab73f8123bbc2b48905c90d1a4b00cf848b028f1e81e623257f2` | — | ✅ shared instance, 6 databases | — |
| — | GreenMail **2.1.3** (`greenmail/standalone:2.1.3`) | image `sha256:d6db42a4fc258fec0948b1ae7b579fd06947cc92087c162ec0597972a6c36850` | — | ✅ IMAP 3143 / SMTP 3025 | mailbox `test@localhost` |

\* JSON:API is **not a core module in Drupal 8.6** (added to core in 8.7). State (ii) uses the
contributed `drupal/jsonapi` **8.x-1.24** (`sha256:141bcabf80c9084699f1dc7b23a6303ee53042f0abcf42c46e2aac279a116e30`,
from ftp.drupal.org). See §4.

## 2. Running containers (all ports loopback-only)

| Container | Image (pinned) | Loopback port | Status |
|---|---|---|---|
| pilot-db | mariadb@sha256:7db29378…257f2 | 127.0.0.1:13306→3306 | up (healthy) |
| pilot-wp-vuln | wordpress@sha256:43693c77…547b (6.7.1-apache) | 127.0.0.1:8081→80 | up |
| pilot-wp-fixed | wordpress@sha256:43693c77…547b (6.7.1-apache) | 127.0.0.1:8082→80 | up |
| pilot-drupal-vuln | drupal@sha256:d6073e2f…97f0 (8.6.9-apache) | 127.0.0.1:8083→80 | up |
| pilot-drupal-fixed | drupal@sha256:8eec1950…feca (8.6.10-apache) | 127.0.0.1:8084→80 | up |
| pilot-roundcube-vuln | roundcube/roundcubemail@sha256:0ee2f1b7…628c (1.4.3-apache) | 127.0.0.1:8085→80 | up |
| pilot-roundcube-fixed | roundcube/roundcubemail@sha256:de8facfa…57cc (1.4.4-apache) | 127.0.0.1:8086→80 | up |
| pilot-imap | greenmail/standalone@sha256:d6db42a4…6850 (2.1.3) | 127.0.0.1:3143→IMAP, 127.0.0.1:3025→SMTP | up |

Verified with `ss -tlnp`: every published port is `127.0.0.1`. (`3110/3465/3993/3995/8080`
inside the GreenMail container are **not** published.)

Raw evidence: `artifacts/http-verification.txt`, `artifacts/vm-inventory.txt`.

## 3. HTTP smoke checks (loopback)

| Instance | Endpoint | Result |
|---|---|---|
| wp-vuln | `/` · `/wp-login.php` · `/wp-json/` | 200 · 200 · 200 |
| wp-vuln | plugin asset version on `/wp-login.php` | **`ver=9.1.1.1`** |
| wp-fixed | plugin asset version on `/wp-login.php` | **`ver=9.1.2`** |
| both WP | `<meta name="generator">` | `WordPress 6.7.1` |
| drupal-vuln/-fixed | `/` · `/core/install.php` · `/core/CHANGELOG.txt` | 200 · 200 · 200 |
| drupal state (i) | `GET /node/1?_format=hal_json` (basic auth) | **200** (REST on) · JSON:API 404 |
| drupal state (ii) | `GET /jsonapi/node/article` | **200** (JSON:API on) · REST 403 |
| drupal state (iii) | both endpoints | 403 / 404 |
| roundcube-vuln/-fixed | `GET /?_task=login` | 200 (login page) |
| roundcube (functional) | POST login `test`/`test` | **302**; IMAP log `LOGIN completed` |
| imap | `:3143` banner | `* OK IMAP4rev1 Server GreenMail v2.1.3 ready` |

Config-state ground truth (drush / wp-cli) was used only to build and label the states — it is
**not** scanner input (D-003).

## 4. Blockers / findings (need researcher attention)

1. **Drupal 8.6 has no JSON:API core module.** The pilot plan's state (ii) (REST off + JSON:API on)
   is not reachable on a stock `drupal:8.6.x` image. Realised here with contrib `drupal/jsonapi`
   8.x-1.24. *Decision needed:* (a) accept the contrib module in the registry, (b) shift the case
   to Drupal 8.7+ where JSON:API is core, or (c) drop state (ii) for 8.6. Not decided here.
2. **Drush for Drupal 8.6:** the `drush/drush:9` image ships PHP 7.0.7 (below Drupal 8.6's PHP
   floor), and a default global Composer install pulls Twig 2 (breaks Drupal 8.6's Twig 1).
   Resolved by installing Drush 9.7.3 with Composer 2.2.25 and **pinning `twig/twig:^1.38`**.
3. **Roundcube image ships no PHP `imap` extension.** Roundcube 1.4 uses its own pure-PHP IMAP
   client, so login works anyway; but any tooling that assumes `ext-imap` will not work in-image.
4. **Version observability for the method is uneven:** WordPress exposes the plugin version in a
   login-page asset (`ver=9.1.x`); Drupal 8.6's `/core/CHANGELOG.txt` carries **no version string**
   and Roundcube's `/CHANGELOG` is **403**. Fingerprinting these may rely on weaker signals — a
   result worth recording for R1 (observability), not a deployment failure.
5. **MariaDB version vs old apps:** MariaDB 10.11 worked for WordPress 6.7, Drupal 8.6 and Roundcube
   1.4 installs. Reset between runs: `docker compose down -v` (drops the `mariadb-data` volume) then
   `up -d`; app bind-mount dirs under `wordpress/*/html` and `drupal/*/html` must be cleared too.

## 5. Conclusion

- **All three CVE environments are deployable on the lab VM for the pilot** (affected + fixed
  builds run; required configuration states are buildable), with the JSON:API caveat in §4.1.
- Ca A and Ca C are cleanly self-contained (plugin zip / image tag + DB + IMAP).
- Ca B needs one extra asset (contrib JSON:API 1.24) or a version bump to satisfy state (ii).
- No PoC was executed; no CGI enabled; all exposure is loopback.

## 6. Reproduce (exact commands, from the lab VM)

```bash
# state lives at ~/pilot-lab on <lab-user>@<lab-ip>
mkdir -p ~/pilot-lab/{db-init,wordpress/vuln/html,wordpress/fixed/html,drupal/vuln/html,drupal/fixed/html,releases,artifacts,scripts}
# copy compose/docker-compose.yml, compose/db-init/01-init.sql, releases/*, scripts/* (this folder)
cd ~/pilot-lab && docker compose up -d
# Drupal images bake their code into /var/www/html, so pre-populate the bind dirs:
docker run --rm -v "$PWD/drupal/vuln/html:/dest"  --entrypoint bash drupal:8.6.9-apache  -c 'cp -a /var/www/html/. /dest/ && chown -R 33:33 /dest'
docker run --rm -v "$PWD/drupal/fixed/html:/dest" --entrypoint bash drupal:8.6.10-apache -c 'cp -a /var/www/html/. /dest/ && chown -R 33:33 /dest'
docker compose up -d --force-recreate drupal-vuln drupal-fixed
bash scripts/10-wp-setup.sh        # Ca A: install WP + plugin versions
bash scripts/11-wp-2fa.sh          # Ca A: 2FA ON/OFF states
bash scripts/20-drupal-setup.sh pilot-drupal-vuln  drupal_vuln  "Pilot Drupal 8.6.9"
bash scripts/20-drupal-setup.sh pilot-drupal-fixed drupal_fixed "Pilot Drupal 8.6.10"
bash scripts/21-drupal-modules.sh pilot-drupal-vuln  8083
bash scripts/21-drupal-modules.sh pilot-drupal-fixed 8084
bash scripts/30-roundcube-verify.sh
bash scripts/90-http-checks.sh
```

Credentials used are **lab-internal only** (`labuser/<lab-db-pass>`, `admin/<lab-admin-pass>`,
`test/test`); the SSH password for the VM is never written to the workspace.

## 7. Reproduction results (2026-10-07) — ground-truth anchoring

Scripts: `scripts/repro/40-ca-A.sh`, `41-ca-B.sh`, `50-ca-C-send-email.py`,
`42-ca-C.js`, `gen-gadget.php`. Raw evidence: `artifacts/reproduce-ca-*.txt`,
`artifacts/reproduce-ca-C-browser.json`, screenshots + sanitized HTML.
All activity was loopback-only; the Ca B marker command was the harmless
`echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker`.

| Ca | State (config) | Actual outcome | Label |
|---|---|---|---|
| A CVE-2024-10924 | 9.1.1.1 + 2FA ON | unauthenticated `POST .../two_fa/skip_onboarding` → **200 + `wordpress_logged_in` cookie**; `/wp-admin/users.php` → 200, admin bar, no login form | **Applicable** |
| A | 9.1.1.1 + 2FA OFF | route not registered → `404 rest_no_route`; no cookie | **Not Applicable** (missing 2FA precondition) |
| A | 9.1.2 + 2FA ON | `check_login_and_get_user()` now `wp_die()`s → HTTP **500**, no cookie | **Not Applicable** (patched) |
| B CVE-2019-6340 | 8.6.9 REST on | `POST /node?_format=hal_json` (basic auth) → HTTP 500 **but marker created** | **Applicable** |
| B | 8.6.9 REST off + JSON:API on | JSON:API `POST /jsonapi/node/article` → HTTP 500 **but marker created** | **Applicable** (one path off is not enough) |
| B | 8.6.9 both off | REST 406 / JSON:API 404 → no marker | **Not Applicable** |
| B | 8.6.10 REST on (fixed) | `unserialize(..., ['allowed_classes' => FALSE])` → no marker | **Not Applicable** (patched) |
| C CVE-2020-12625 | 1.4.3 | CDATA emitted unescaped → `<script>` reaches browser and runs (console marker) | **Applicable** |
| C | 1.4.4 (fixed) | CDATA `htmlspecialchars()`-escaped → no execution | **Not Applicable** (patched) |

Findings that affect the protocol (not deployment failures):

1. **Successful Ca B exploitation answers HTTP 500, not 200.** The gadget fires in
   `__destruct` and the request then errors while storing the object. A 5xx alone
   is therefore *not* evidence of failure — the out-of-band marker is required.
2. **Ca B needed authentication in this deployment.** The project's
   `rest.resource.entity_node` config requires `basic_auth`; an unauthenticated
   `POST /node?_format=hal_json` returns `401 No authentication credentials provided`.
   The pilot plan assumed unauthenticated; the reproduction used basic-auth `admin`
   (and added one `field_link` (type `link`) field to `article` as fixture). The
   JSON:API state (ii) uses contrib `drupal/jsonapi` 8.x-1.24 per D-014.
3. **"2FA on" has an indirect unauthenticated HTTP signal** (R1): the `two_fa` REST
   routes exist only when 2FA is enabled, so `POST` with a missing param gives
   `400 rest_missing_callback_param` (2FA on) vs `404 rest_no_route` (2FA off).
4. **Roundcube version is NOT observable unauthenticated**: login-page assets carry
   only a 10-digit cache-buster (`?s=1582145757`), `/CHANGELOG` / `/INSTALL` / etc.
   are 403, and the `Server` header shows only Apache. (The 1.4.4 fix is specifically
   "Fix XSS issue in handling of CDATA in HTML messages".)
5. The fixed 9.1.2 path aborts with `wp_die()` (HTTP 500) rather than a clean 403.
