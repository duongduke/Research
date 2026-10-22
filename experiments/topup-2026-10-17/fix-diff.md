# Fix diff & mechanism — CVE-2023-23752 and CVE-2023-6553

> **Method:** static reading and byte comparison of the **persisted release
> packages** in `downloads/` (the same files hashed in `manifest.md`). **Nothing was
> executed**: no container, no web installer, no request, no PoC, no PHP run.
>
> **Labels:** `KNOWN` = read directly from the package bytes/diff, and the exact
> file + snippet is quoted below. `ASSUMED` = carried over from
> `notes/cve-verification-topup-2026-10-17.md` as unverified in step 1 (no runtime
> evidence). This file assigns **no ground-truth label**; both CVEs remain
> unlabeled under D-035.
>
> **Provenance:** the affected/fixed versions, CWE and CVSS in the report come from
> the vendor/NVD/CVE.org records persisted in `sources/`. The code claims below were
> re-checked against the packages (not merely copied from the report).

---

## 1. CVE-2023-23752 — Joomla! CMS 4.0.0–4.2.7, improper access check in webservice endpoints

Fixed in **4.2.8**. The defect is a **query-parameter override of a route default**
plus an **access check that trusts the resulting flag**.

### 1.1 KNOWN — the route declares `public => false` (protected by default)

`sources` → package path `plugins/webservices/config/config.php` (4.2.7):

```php
$defaults    = ['component' => 'com_config'];
$getDefaults = array_merge(['public' => false], $defaults);

$routes = [
    new Route(['GET'], 'v1/config/application', 'application.displayList', [], $getDefaults),
    new Route(['PATCH'], 'v1/config/application', 'application.edit', [], $defaults),
    ...
];
```

So `GET v1/config/application` is *intended* to require authentication
(`public` defaults to `false`), while `PATCH` has no `public` key at all.

### 1.2 KNOWN — the merge that lets `?public=true` win (4.2.7)

`libraries/src/Router/ApiRouter.php`, 4.2.7 (`sha256 3477fb51…2cfe69`), lines 102/109/116:

```php
        $query = Uri::getInstance()->getQuery(true);          // line 102
        ...
                    $vars = $route->getDefaults();            // line 109
                    ...
                    $vars       = array_merge($vars, $query); // line 116  <-- query overrides defaults
                    return ['controller' => …, 'task' => …, 'vars' => $vars];
```

`array_merge($vars, $query)` places the **request query string last**, so
`?public=true` replaces the route's `public => false`.

### 1.3 KNOWN — the consumer of the flag (unchanged in 4.2.8)

`libraries/src/Application/ApiApplication.php`, line 304:

```php
        if (!isset($route['vars']['public']) || $route['vars']['public'] === false) {
            if (!$this->login(['username' => ''], ['silent' => true, 'action' => 'core.login.api'])) {
                throw new AuthenticationFailed();
            }
        }
```

**This file is byte-identical in 4.2.7 and 4.2.8**
(`sha256 c314f453704cad1d1d276a35ada3f98ed42f9b8c23ece5bf6cb55d30488d93f3` in both
zips). The authentication logic was not changed by the fix; only the value it
receives was.

**Correction of a wording in the step-1 brief (recorded for accuracy):** the
`array_merge` of the query is **not** in `ApiApplication.php` — it is in
`ApiRouter.php` (§1.2). `ApiApplication.php` only consumes `$route['vars']['public']`.
The 4.2.8 patch is in `ApiRouter.php` only.

### 1.4 KNOWN — the 4.2.8 patch (full hunk)

`libraries/src/Router/ApiRouter.php`, 4.2.7 → 4.2.8
(`3477fb51…2cfe69` → `867187fc…f9d692`):

```diff
@@ -101,6 +101,11 @@
         $query = Uri::getInstance()->getQuery(true);
 
+        // Remove the public key as it is only supported coming from the route definition
+        if (array_key_exists('public', $query)) {
+            unset($query['public']);
+        }
+
         // Iterate through all of the known routes looking for a match.
@@ -113,6 +118,8 @@
                     $controller = preg_split("/[.]+/", $route->getController());
+
+                    /** @deprecated  4.3  Query parameters will not be merged into route variables from 5.0 */
                     $vars       = array_merge($vars, $query);
```

The fix is a **deny-list on one key** (`public`); the general merge is kept (and only
marked deprecated). Consequence for reproduction: on 4.2.8 the query cannot set
`public`, the route default `false` stands, and `ApiApplication` throws
`AuthenticationFailed`.

### 1.5 KNOWN — nothing else behavioural changed in 4.2.8

Mechanical comparison of the two packages by entry name + CRC (12,091 entries each,
no entry added or removed): **39 entries differ**. Of those, the only **behavioural
PHP source change** is `libraries/src/Router/ApiRouter.php`. The rest are:

- `libraries/src/Version.php` — version constants (release bump);
- language/manifest XML (`installation/language/…`, `administrator/manifests/…`, `api/language/…`, `language/en-GB/…`);
- `media/**/joomla.asset.json` and `plugins/system/webauthn/fido.jwt` — asset/version metadata;
- `libraries/vendor/{autoload.php,composer/*}` — Composer autoload/installed metadata.

This matches the report's "the 4.2.8 patch differs only in `ApiRouter.php`" claim at
the **code** level. It does **not** prove equivalence at runtime.

### 1.6 KNOWN — the config plugin ships enabled

`installation/sql/mysql/base.sql` (4.2.7), insert block with columns
`(package_id, name, type, element, folder, client_id, enabled, access, protected, locked, manifest_cache, params, custom_data, ordering, state)`:

```sql
(0, 'plg_webservices_config', 'plugin', 'config', 'webservices', 0, 1, 1, 0, 1, '', '{}', '', 2, 0),
```

Column 7 is `enabled` = **1** → the webservice `com_config` routes exist on a
**default fresh install**. This is install-SQL evidence only: it was *not* confirmed
against a running instance (no install was performed).

### 1.7 KNOWN — the endpoint returns the global configuration object

- `api/components/com_config/src/Controller/ApplicationController.php`, `displayList()`
  (line 55) performs **no** access check; only `edit()` (line 95) calls
  `$this->allowEdit()` (line 105) and throws `NotAllowed` otherwise.
- `administrator/components/com_config/src/Model/ApplicationModel.php`, `getData()` (line 91):

```php
    public function getData()
    {
        // Get the config data.
        $config = new \JConfig();
        $data   = ArrayHelper::fromObject($config);

        // Get the correct driver at runtime
        $data['dbtype'] = $this->getDatabase()->getName();
        ...
```

So the disclosed object is the site's **global configuration** (`\JConfig`: DB
host/user/password/name/prefix, mail settings, secret), not a content record. This is
information disclosure, not code execution.

### 1.8 KNOWN — the package does not block `/api/`

The 4.2.7 package contains no `api/.htaccess` (the only root-level `.htaccess` shipped
is `libraries/.htaccess`). With default Apache `AllowOverride`/`index.php` handling,
`/api/index.php/...` is reachable directly. This is a **package-level** fact; the
deployment's web-server config is still a deployment variable.

### 1.9 ASSUMED (unverified in step 1 — no request was sent)

- `/api/index.php` is reachable **without** SEF/rewrite on the chosen image
  (default Apache runs `index.php` directly).
- **Version observability over HTTP**: the package contains
  `administrator/manifests/files/joomla.xml` and `language/en-GB/langmetadata.xml`
  with `<version>`, but **no request was sent** to check they return 200
  unauthenticated.
- The web installer (`/installation/index.php`) or a CLI install works on the chosen
  PHP 8.x + MariaDB image (nothing was executed); `configuration.php` must be created.
- A JSON:API response of the expected shape is returned by
  `GET /api/index.php/v1/config/application?public=true` (mechanism is derived from
  code, not observed).

### 1.10 Step-2 consequence (plan, not a result)

Per **D-035 §4**, the step-2 reproduction success criterion is **the actual leaked
canary config value** (e.g. the planted DB password / `secret` string placed in
`configuration.php`), **not** merely the presence of key names (`db`, `user`,
`password`) and **not** an HTTP 200. An unauthenticated 200 carrying a recognisable
canary value is what distinguishes "Applicable" from "endpoint exists but discloses
nothing usable". The 4.2.8 control must return `AuthenticationFailed` (or otherwise
not the canary) in the same environment.

---

## 2. CVE-2023-6553 — WordPress plugin Backup Migration (`backup-backup`) ≤ 1.3.7, unauthenticated RCE

Fixed in **1.3.8**. The defect is **client-controlled header values flowing into
`define()`/`require_once`**, which turns a PHP filter chain into code execution.

### 2.1 KNOWN — the 1.3.7 entry point

`backup-backup/includes/backup-heart.php`, 1.3.7
(`sha256 8796fcf29979b8c714b03359e088e8e16dc0df99d3067d32472cfed88e74327f`):

```php
  // Allow only POST requests
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') {     // lines 6-9
    exit;
  }
  ...
  // Get fields from header
  if (isFunctionEnabled('getallheaders')) {
    $fields = getallheaders();
  }
  ...
  foreach ($fields as $key => $value) {            // lines 42-46: header names lowercased
    $buffer = $value;
    unset($fields[$key]);
    $fields[strtolower($key)] = $value;
  }
  ...
  define('ABSPATH', $fields['content-abs']);        // line 53
  ...
  define('BMI_ROOT_DIR', $fields['content-dir']);   // line 62
  define('BMI_INCLUDES', BMI_ROOT_DIR . 'includes');// line 64
  ...
    require_once BMI_INCLUDES . '/bypasser.php';    // line 118
```

- No authentication, no nonce, no `wp-load.php` include: the file is standalone and
  reads `Content-*` headers supplied by the caller.
- `includes/.htaccess` (233 bytes) **grants** access to `*.php` and disables rewrites:

```apache
<Files *.php>
  <IfModule mod_authz_core.c>
    Require all granted
  </IfModule>
  ...
</Files>
<IfModule mod_rewrite.c>
  RewriteEngine off
</IfModule>
```

(nginx ignores `.htaccess` entirely, so the file is reachable there too — general
web-server behaviour, not measured here.)

### 2.2 KNOWN — the 1.3.8 patch: `filterChainFix()`

`backup-backup/includes/backup-heart.php`, 1.3.8
(`sha256 31379471e1fcf3d83c89e8f502aa6aafecfa863ebee7d839946e8dbddec70ae3`):

```php
  // Filter and prevent PHP filter injection
  function filterChainFix($content) {

    // Make sure it exist and is string
    if (!is_string($content)) die("Incorrect parameters.");

    // Check if it's not larger than max allowed path length (default systems)
    if (strlen($content) > 256) die("Incorrect parameters.");

    // Check if the path does not contain "php:"
    if (strpos($content, "php:")) die("Incorrect parameters.");

    // Check if the path contain "|", it's not possible to use this character with our backups paths
    if (strpos($content, "|")) die("Incorrect parameters.");

    // Check if the directory/file exist otherwise fail
    if (!(is_dir($content) || file_exists($content))) die("Incorrect parameters.");

    // Return correct content
    return $content;

  }
```

Applied at **all five** sink sites (1.3.8 lines 76, 85, 141, 146, 147):

```diff
-  define('ABSPATH', $fields['content-abs']);
+  define('ABSPATH', filterChainFix($fields['content-abs']));
...
-  define('BMI_ROOT_DIR', $fields['content-dir']);
+  define('BMI_ROOT_DIR', filterChainFix($fields['content-dir']));
...
-    require_once BMI_INCLUDES . '/bypasser.php';
+    require_once filterChainFix(BMI_INCLUDES) . '/bypasser.php';
     $request = new BMI_Backup_Heart(true,
       ...
-      $fields['content-abs'],
-      $fields['content-dir'],
+      filterChainFix($fields['content-abs']),
+      filterChainFix($fields['content-dir']),
```

**Mechanism the patch confirms (KNOWN, from the shape of the fix):** a working 1.3.7
payload must (a) be ≤ 256 chars, (b) contain `php:` and `|`, and (c) name something
that is *not* an existing file/dir. Those are exactly the PHP filter-chain primitives
(`php://filter/…|…`), so the fix is evidence **for the include → filter-chain vector**,
not merely a generic input sanitisation.

### 2.3 KNOWN — 1.3.8 is a multi-change release

Entry-level diff 1.3.7 → 1.3.8 (same 4 files differ, nothing added/removed):
`backup-backup.php` (version header), `includes/backup-heart.php` (the CVE fix),
`includes/ajax.php`, `readme.txt`. The `ajax.php` change is an unrelated hardening
(local-storage directory name whitelist):

```diff
+      if (!preg_match("/^[a-zA-Z0-9\_\-\/]+$/", $dir_path)) {
+        return ['status' => 'msg', 'why' => __('Entered directory/path name does not match allowed characters (Local Storage).', 'backup-backup'), 'level' => 'warning'];
+      }
```

`readme.txt` (1.3.8) states: `= 1.3.8 =` → `* [FIX] Patched reported CVE - please upgrade`
→ this is the independent, in-package confirmation that 1.3.8 is the fix release.
Package metadata: `Version: 1.3.7` / `1.3.8`, `Stable tag: 1.3.7` / `1.3.8`.

### 2.4 Patch references available for this CVE

From the report (NVD `Patch` tag), no commit SHA was recorded:

- `https://plugins.trac.wordpress.org/browser/backup-backup/tags/1.3.7/includes/backup-heart.php#L38`
- `…#L62`, `…#L64`, `…#L118`

No WordPress.org SVN **changeset** id and no commit hash appears in the step-1 report,
and none was fetched in this persistence step (no network). The authoritative
diff used here is therefore the **tag-to-tag byte comparison** of the two release
zips, which is reproducible offline from `downloads/`.

### 2.5 ASSUMED (unverified in step 1 — nothing was executed)

- The PHP filter chain actually works on the chosen PHP image + extension/ini set
  (`allow_url_include` etc.); **not tested**.
- **Active vs installed**: whether `includes/backup-heart.php` is reachable and
  exploitable when the plugin is *installed but inactive*. The file does not load
  WordPress and defines its own `ABSPATH`, so "installed only" is plausible but
  **unmeasured** — and it is the decisive question for the negative-label branch
  (D-035 §2: measure, do not assume).
- Unauthenticated version observability via
  `/wp-content/plugins/backup-backup/readme.txt` (`Stable tag: 1.3.7`) — no request was
  sent.
- Reusing the lab's existing `wordpress:6.7.1-apache` stack for the plugin — untested.
- Success signal must be **out-of-band** (marker file/script execution), because the
  endpoint echoes text regardless of outcome (D-015 rule; the file `echo`es
  "This is server side script…" — KNOWN from source, but the exact response body was
  not observed).

---

## 3. What this document does **not** establish

- No **label** (Applicable / Not Applicable / Unresolved) for either CVE — D-035 assigns
  none at step 1.
- No runtime applicability, no reproduction, no exploitability measurement, no
  HTTP-observability verification. Every behavioural claim above is static.
- No **CISA KEV** statement about CVE-2023-23752: the KEV feed returned **403**; NVD
  carries a reference pointing at KEV, which is not independent confirmation. See
  `manifest.md` §3 (`sources/kev.json` = Akamai access-denied HTML, not JSON).
