# Registry — RQ-C1 26-CVE build (case = `(product, version/build, configuration, CVE)`)

> Created 2026-10-10 by the lab agent for Batch 0. Fields per `notes/lab-spec-26-cve-2026-10-10.md` §2.
> **Batch 0 (5 cases) is filled**; the other 21 rows are `TODO` (Batches 1–4 not started — STOP after Batch 0).
> Details + artifacts for each filled case live in `CVE-*/README.md` and `CVE-*/artifacts/`.
> Labels are ground truth (advisory range + sandbox reproduction), independent of any scanner output (D-003).

## Legend
- `label`: `Applicable` / `Not Applicable` (+ nhánh **a** = version outside range / patched, **b** = affected but every impact path blocked) / `Unresolved`.
- `access_model`: `unauth` / `auth(<role>)`.
- `scenario_tags`: subset of `backport` / `config-tắt` / `ẩn-version` / `CPE-sai`; "—" = no real case.

## Table (1 row per case; 16 fields)

| cve_id | product | type_cwe | affected_range | fixed_version | vuln_build | fixed_build | config_states | access_model | fixture | preconditions | repro_method | label | scenario_tags | inclusion_reason | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2021-42013 | Apache httpd | path traversal (biến thể) / CWE-22 | 2.4.49–2.4.50 | 2.4.51 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #2, biến thể của 41773 | Batch 1 |
| CVE-2014-3704 | Drupal core | SQLi (Drupalgeddon) / CWE-89 | 7.x < 7.32 | 7.32 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #3 | Batch 1 |
| CVE-2018-7600 | Drupal core | RCE (Drupalgeddon2) / CWE-20 | <7.58; 8.x<8.3.9; 8.4.x<8.4.6; 8.5.x<8.5.1 | 7.58/8.3.9/8.4.6/8.5.1 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #4; RCE→marker | Batch 1 |
| CVE-2018-7602 | Drupal core | RCE (Drupalgeddon3) / CWE-94 | 7.x<7.59; 8.x<8.5.3 | 7.59/8.5.3 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #5; RCE→marker | Batch 1 |
| CVE-2020-13671 | Drupal core | file upload→RCE / CWE-434 | 7.x<7.74; 8.8.x<8.8.11; 8.9.x<8.9.9; 9.0.x<9.0.8 | 7.74/8.8.11/8.9.9/9.0.8 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #29; RCE→marker | Batch 1 |
| CVE-2019-6341 | Drupal core | stored XSS (file upload) / CWE-79 | 7.x<7.65; 8.5.x<8.5.14; 8.6.x<8.6.13 | 7.65/8.5.14/8.6.13 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #30 | Batch 1 |
| CVE-2020-25213 | WP plugin File Manager | RCE (upload PHP) / CWE-434 | <6.9 | 6.9 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #7; RCE→marker | Batch 2 |
| CVE-2024-28000 | WP plugin LiteSpeed Cache | leo quyền / CWE-266 | ≤6.3.0.1 | 6.4 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #8; cần hiểu điều kiện hash/crawler | Batch 2 |
| CVE-2023-32243 | WP plugin Essential Addons | auth bypass / CWE-287 | 5.4.0–5.7.1 | 5.7.2 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #10 | Batch 2 |
| CVE-2023-3460 | WP plugin Ultimate Member | leo quyền / account takeover / CWE-269 | <2.6.7 | 2.6.7 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #22 | Batch 2 |
| CVE-2020-35489 | WP plugin Contact Form 7 | file upload→RCE / CWE-434 | <5.3.2 | 5.3.2 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #23; RCE→marker | Batch 2 |
| CVE-2019-10692 | WP plugin WP Google Maps | SQLi (REST) / CWE-89 | <7.11.18 | 7.11.18 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #24 | Batch 2 |
| CVE-2024-27956 | WP plugin WP Automatic | SQLi (unauth) / CWE-89 | ≤3.92.0 | 3.92.1 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #25 | Batch 2 |
| **CVE-2021-24284** | WP plugin Kaswara | file upload→RCE / CWE-434 | ≤3.0.1 | discontinued (no fix) | **none available** (official CDN+SVN 404; no Wayback; only nulled resale) | n/a | not built | unauth | — | — | not reproducible | **Unresolved** | — | verified #26; flagged source risk → Batch 0 de-risk | **FEASIBILITY FAILURE** — no trustworthy source for 3.0.1 (`CVE-2021-24284/README.md`) |
| CVE-2017-1001000 | WP core | content injection / auth bypass (REST) / authz | 4.7.0–4.7.1 | 4.7.2 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #16 | Batch 3 |
| **CVE-2019-8942** | WP core | RCE (image Exif/crop) / chain: post-meta→CWE-22→LFI | <4.9.9; 5.x<5.0.1 | 4.9.9/5.0.1 | `wordpress:5.0.0-apache` @sha256:871ae0eb… (PHP 7.2.13) | `wordpress:5.0.1-apache` @sha256:33da10a3… | 5.0.0 vuln / 5.0.1 fixed; author acct; default theme; GD; Listen 8111 | **auth(author)** | author acct + crafted JPEG `payload-8942.jpg` (sha256 890f97ba…) | version∈range (P1) ∧ auth author (P2) ∧ image-editor/self-fetch (P3) ∧ `meta_input` unfiltered (P4) | upload→`meta_input[_wp_attached_file]`=…`?/../../themes/…`→crop→`_wp_page_template` LFI→marker | **Applicable** (5.0.0) / **Not Applicable a** (5.0.1) | — (no case) | verified #17; flagged author precondition → Batch 0 | `CVE-2019-8942/README.md` |
| **CVE-2021-29447** | WP core | XXE (Media Library/getID3) / CWE-611 | 5.6.0–5.7.0 (<5.7.1) **+ PHP 8** | 5.7.1 | `wordpress:5.7.0-php8.0-apache` @sha256:0632e568… (PHP 8.0.3) | `wordpress:5.7.1-php8.0-apache` @sha256:fb3de10a… (PHP 8.0.6) | 5.7.0 vuln / 5.7.1 fixed; PHP 8; author acct; attacker DTD listener | **auth(author)** | author acct + malicious WAV (`29447-payload.wav`) + `evil.dtd` on `attacker:8000` | version∈range ∧ **PHP 8** ∧ author upload ∧ getID3 external entities | author uploads WAV → iXML XXE → fetch evil.dtd → exfil marker (OOB) | **Applicable** (5.7.0) / **Not Applicable a** (5.7.1) | — (no case) | verified #18; flagged PHP 8 precondition → Batch 0 | `X-Powered-By: PHP/8.0.3` observable; `CVE-2021-29447/README.md` |
| **CVE-2022-21661** | WP core | SQLi (WP_Query) / CWE-89 | <5.8.3 | 5.8.3 | `wordpress:5.8.2-apache` @sha256:fc33b796… (PHP 7.4.27) | `wordpress:5.8.3-apache` @sha256:70246a8d… | 5.8.2 vuln / 5.8.3 fixed; fixture plugin active | **unauth** | **Ele Custom Skin 3.1.3** (`ele-custom-skin.3.1.3.zip` sha256 5c490eaa…), `wp_ajax_nopriv_ecsload`→`new WP_Query($_POST['query'])` | version∈range ∧ a plugin/theme passing user input to WP_Query (fixture) | `POST admin-ajax action=ecsload` + `tax_query.terms` SLEEP(5) → time signal + DB log | **Applicable** (5.8.2) / **Not Applicable a** (5.8.3) | fixture-dependent (config-tắt-adjacent); no backport/hidden-version/CPE | verified #19; flagged fixture precondition → Batch 0 | `CVE-2022-21661/README.md` |
| CVE-2015-3440 | WP core | stored XSS (comment) / CWE-79 | <4.2.1 | 4.2.1 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #20 | Batch 3 |
| CVE-2023-2745 | WP core | path traversal (wp_lang) / CWE-22 | ≤6.2 | 6.2.1 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #21 | Batch 3 |
| CVE-2021-44026 | Roundcube | SQLi (search) / CWE-89 | <1.3.17; 1.4.x<1.4.12 | 1.3.17/1.4.12 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #11 | Batch 4 |
| CVE-2023-5631 | Roundcube | stored XSS (SVG) / CWE-79 | <1.4.15; 1.5.x<1.5.5; 1.6.x<1.6.4 | 1.4.15/1.5.5/1.6.4 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #12 | Batch 4 |
| CVE-2024-37383 | Roundcube | stored XSS (SVG animate) / CWE-79 | <1.5.7; 1.6.x<1.6.7 | 1.5.7/1.6.7 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #13 | Batch 4 |
| CVE-2020-12640 | Roundcube | path traversal / LFI / CWE-22 | <1.4.4 | 1.4.4 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #15 | Batch 4 |
| CVE-2020-12641 | Roundcube | RCE (command injection, im_convert_path) / CWE-78 | <1.4.4 | 1.4.4 | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | verified #28; RCE→marker; cần ImageMagick path | Batch 4 |
| **CVE-2021-23017** | nginx (resolver) | off-by-one (memory) | 0.6.18–1.20.0 | 1.20.1/1.21.0; Ubuntu jammy **1.18.0-6ubuntu9** (backport) | `rq-c1/nginx-jammy-backport:1.18.0` (base `ubuntu@sha256:5ec03bb3…` 22.04); installed `nginx 1.18.0-6ubuntu14.21` | n/a (fixed-version case) | jammy container, loopback `127.0.0.1:8190` | unauth | — | build is patched (Ubuntu backport) | header observation + `dpkg -l` (ground truth only); no exploitation | **Not Applicable a (đã vá)** | **backport** (+ ẩn-version/build-identity limitation) | verified #27; special case per spec §6 → Batch 0 | exact `-6ubuntu9` superseded by `-6ubuntu14.21`; VM is 24.04 → jammy container (`CVE-2021-23017/README.md`) |

## Batch 0 summary

| # | CVE | Status | Label |
|---|---|---|---|
| 14 | CVE-2021-24284 | feasibility failure | Unresolved (no source) |
| 16 | CVE-2019-8942 | built + labeled | Applicable / Not Applicable (a) |
| 17 | CVE-2021-29447 | built + labeled | Applicable / Not Applicable (a) |
| 18 | CVE-2022-21661 | built + labeled | Applicable / Not Applicable (a) |
| 26 | CVE-2021-23017 | built + labeled | Not Applicable (a, backport) |

Counts so far (`notes/ground-truth-protocol.md` R4):
`n_unique_cves (Batch 0) = 5` (of which 1 Unresolved); `n_deployments = 7`
(6 WP containers + 1 nginx); `n_cases = 7` (3 WP CVEs × affected+fixed = 6, + nginx = 7);
`n_observation_conditions = 7` (version signals ×6 + nginx header/revision split).

---

## Appendix A — Replacement case + Batch 2 rows (filled), 2026-10-10

### Replacement (substituted for the failed CVE-2021-24284, per researcher decision)

| cve_id | product | type_cwe | affected_range | fixed_version | vuln_build | fixed_build | config_states | access_model | fixture | preconditions | repro_method | label | scenario_tags | inclusion_reason | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2023-5798** | WP plugin Assistant | SSRF / **CWE-918** | Assistant `< 1.4.4` | 1.4.4 | `assistant.1.4.3.zip` sha256 `69af275424b02d4fd8d892078f90f3b4512bcd0a37cad1279716da178fd3c9fb` | `assistant.1.4.4.zip` sha256 `1e305811ffe6bd73a729e13e3d5982bf2d44106f851b3023830b6ddeca07a7b9` | WP 6.7.1 + Assistant 1.4.3 (vuln) / 1.4.4 (fixed) | **auth(Editor+)** | editor acct; `fl_asst_image_proxy&url=` | version∈range ∧ Editor+ (`edit_others_posts`) ∧ proxy unvalidated | `GET /?fl_asst_image_proxy&url=http://attacker:8000/rq-c1-ssrf` → attacker listener hit | **Applicable** (1.4.3) / **Not Applicable a** (1.4.4) | `ẩn-version` (plugin ver not unauth-observable) | substitute for failed Kaswara; adds SSRF CWE; new distinct ID | `CVE-2023-5798/README.md` |

### Batch 2 rows (#7–#13)

| cve_id | product | type_cwe | affected_range | fixed_version | vuln_build | fixed_build | config_states | access_model | fixture | preconditions | repro_method | label | scenario_tags | inclusion_reason | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2020-25213** | WP plugin File Manager | upload→RCE / CWE-434 | 6.0–6.8 (<6.9) | 6.9 | `wp-file-manager.6.0.zip` sha256 `f70dd0e7…`; nested real plugin sha256 `e4c62af0…` | latest 8.0.6 (`…latest.zip` sha256 `04870c2f…`) | WP 6.1.1-php7.4 + WFM 6.0 / 8.0.6 | unauth | — | connector reachable ∧ upload writable | unauth elFinder upload → GET payload → marker | **Applicable** / **Not Applicable a** | — | verified #7; CISA KEV; RCE→marker | 6.9 zip gone → fixed 8.0.6; `CVE-2020-25213/README.md` |
| **CVE-2024-28000** | WP plugin LiteSpeed Cache | priv-esc / CWE-266 | ≤6.3.0.1 | 6.4 | `litespeed-cache.6.3.0.1.zip` | `litespeed-cache.6.4.zip` | WP 6.1.1-php7.4 + LS 6.3.0.1 / 6.4 | unauth | — | unauth `async_litespeed` handler ∧ weak 6-char hash | trigger hash → forged cookies (hash via DB ground truth) → REST 201 admin | **Applicable** / **Not Applicable a** | — | verified #8 | hash brute-forced out of budget; used server hash (deviation); `CVE-2024-28000/README.md` |
| **CVE-2023-32243** | WP plugin Essential Addons | auth bypass / CWE-287 | 5.4.0–5.7.1 | 5.7.2 | `essential-addons-for-elementor-lite.5.7.1.zip` (+ elementor 3.5.6) | `…5.7.2.zip` | WP 6.1.1-php7.4 + EA 5.7.1/5.7.2 + Elementor | unauth | Elementor dep; admin username | EA active ∧ nonce via `eael_get_token` | reset admin pw → login as admin | **Applicable** / **Not Applicable a** | — | verified #10 | account takeover; `CVE-2023-32243/README.md` |
| **CVE-2023-3460** | WP plugin Ultimate Member | priv-esc / CWE-269 | <2.6.7 | 2.6.7 | `ultimate-member.2.6.6.zip` | `ultimate-member.2.6.7.zip` | WP 6.1.1-php7.4 + UM 2.6.6/2.6.7 | unauth | UM register form (default id 7) + page | open registration ∧ metakey filter bypass | register with `wp_càpabilities[administrator]=1` → admin user | **Applicable** / **Not Applicable a** | — | verified #22 | `CVE-2023-3460/README.md` |
| **CVE-2019-10692** | WP plugin WP Google Maps | SQLi / CWE-89 | 7.11.00–7.11.17 | 7.11.18 | `wp-google-maps.7.11.17.zip` | `wp-google-maps.7.11.18.zip` | WP 6.1.1-php7.4 + plugin pair | unauth | — | `wpgmza/v1/markers` route ∧ unsanitised `fields` | injected `fields` SELECT → controlled marker / user hashes | **Applicable** / **Not Applicable a** | — | verified #24 | plugin needs PHP 7.4; `CVE-2019-10692/README.md` |
| **CVE-2024-27956** | WP plugin WP Automatic | SQLi / CWE-89 | ≤3.92.0 | 3.92.1 | **none available** (plugin removed from wordpress.org; SVN/api 404) | n/a | not built | unauth | — | — | not reproducible | **Unresolved** | — | verified #25 | **FEASIBILITY FAILURE** → **drops total to 29; TOP-UP REQUIRED** (`CVE-2024-27956/README.md`) |
| **CVE-2020-35489** | WP plugin Contact Form 7 | upload→RCE / CWE-434 | <5.3.2 | 5.3.2 | `contact-form-7.5.3.1.zip` (available) | `contact-form-7.5.3.2.zip` (available) | buildable | unauth | CF7 form w/ file field | non-default config required per independent analyses | not reliably reproducible; no fabricated config | **Unresolved** | possible `config-tắt` | verified #23 | `CVE-2020-35489/README.md` |

> **CVE-2021-24284** (Kaswara, earlier feasibility failure) is now **replaced by CVE-2023-5798**; kept as a record above.

## Appendix B — Remaining work NOT completed (STOP condition)

- **Batch 1 (Drupal core + Apache), rows #1–#6: NOT STARTED** — CVE-2021-42013, CVE-2014-3704, CVE-2018-7600,
  CVE-2018-7602, CVE-2020-13671, CVE-2019-6341.
- **Batch 4 (Roundcube), rows #21–#25: NOT STARTED** — CVE-2021-44026, CVE-2023-5631, CVE-2024-37383,
  CVE-2020-12640, CVE-2020-12641.
- Reason: the work instruction mandates **STOP** on a feasibility failure that drops the distinct-CVE
  count below 30. CVE-2024-27956 (removed plugin) and CVE-2020-35489 (Unresolved) already do so; a
  researcher top-up decision is required before continuing.

---

## Appendix C — Continuation status (2026-10-10, final)

**Built + labeled (20 distinct CVEs):** CVE-2019-8942, CVE-2021-29447, CVE-2022-21661, CVE-2021-23017, CVE-2017-1001000, CVE-2023-2745, CVE-2015-3440, CVE-2019-10692, CVE-2020-25213, CVE-2023-32243, CVE-2023-3460, CVE-2024-28000, CVE-2023-5798, CVE-2021-24917, CVE-2023-28121, CVE-2021-42013 (+ pilot: CVE-2021-41773, CVE-2019-6340, CVE-2024-10924, CVE-2020-12625).

**Dropped/replaced (3):** CVE-2021-24284→CVE-2023-5798; CVE-2024-27956→CVE-2021-24917; CVE-2020-35489→CVE-2023-28121 (CVE-2020-35489 recorded Unresolved).

**Batch 1 remaining (BLOCKED — Docker image availability):**
| CVE | product | type | affected | fixed | vuln_build | fixed_build | access | label | note |
|---|---|---|---|---|---|---|---|---|---|
| CVE-2014-3704 | Drupal core 7 | SQLi CWE-89 | 7.x<7.32 | 7.32 | **custom tarball 7.31** (drupal-7.31.tar.gz sha256 `6af4849f…`) — image unpullable | custom 7.32 (`f36d5ab0…`) | unauth | pending | BLOCKED (manifest v1 / Hub rate limit) |
| CVE-2018-7600 | Drupal core | RCE CWE-20 | <7.58; 8.x<8.3.9 | 7.58/8.3.9 | **custom tarball** 7.57 (`…`) | custom 7.58 | unauth | pending | BLOCKED |
| CVE-2018-7602 | Drupal core | RCE CWE-94 | 7.x<7.59; 8.x<8.5.3 | 7.59/8.5.3 | custom 7.58 | custom 7.59 | **auth (delete-node)** | pending | BLOCKED |
| CVE-2020-13671 | Drupal core | upload→RCE CWE-434 | 8.8.x<8.8.11 | 8.8.11 | custom 8.8.10 | custom 8.8.11 | unauth? | pending | BLOCKED |
| CVE-2019-6341 | Drupal core | stored XSS CWE-79 | 7.x<7.65; 8.5.x<8.5.14 | 7.65/8.5.14 | custom 7.64 | custom 7.65 | unauth | pending | BLOCKED |

**Batch 4 remaining:**
| CVE | product | type | affected | fixed | label | note |
|---|---|---|---|---|---|---|
| CVE-2021-44026 | Roundcube | SQLi search CWE-89 | <1.3.17; 1.4.x<1.4.12 | 1.4.12 | pending | authenticated chain; stack built (1.4.11/1.4.12) |
| CVE-2023-5631 | Roundcube | stored XSS SVG CWE-79 | <1.4.15; 1.5.x<1.5.5 | 1.5.5 | pending | stack built (1.5.3/1.5.5); XSS payload not yet executed |
| CVE-2024-37383 | Roundcube | stored XSS SVG animate CWE-79 | <1.5.7; 1.6.x<1.6.7 | 1.5.7 | pending | stack built (1.5.6/1.5.7); payload not yet executed |
| CVE-2020-12640 | Roundcube | path traversal/LFI CWE-22 | <1.4.4 | 1.4.4 | config-gated | official image has **no installer** → impact path blocked |
| CVE-2020-12641 | Roundcube | RCE im_convert_path CWE-78 | <1.4.4 | 1.4.4 | config-gated | no installer + no ImageMagick in image |

**Running counts:** `n_unique_cves` built+labeled = 20; remaining = 10; target ≥30.

---

## Appendix D — Drupal tarball builds (D-022), 2026-10-10

Base image for all: `drupal@sha256:d6073e2f6c662a9406cbe0b00215276ca206ded5e170268a29faa104bf2b97f0` (PHP 7.2.15/Apache 2.4.25).

| cve_id | product | type_cwe | affected | fixed | vuln_build (sha256) | fixed_build (sha256) | access | label |
|---|---|---|---|---|---|---|---|---|
| CVE-2014-3704 | Drupal 7 core | SQLi CWE-89 | 7.x<7.32 | 7.32 | drupal-7.31 `6af4849f…` | drupal-7.32 `f36d5ab0…` | unauth | **Applicable / NA-a** |
| CVE-2018-7600 | Drupal 8 core | RCE CWE-20 | 8.5.x<8.5.1 | 8.5.1 | drupal-8.5.0 | drupal-8.5.1 | unauth | **Applicable / NA-a** |
| CVE-2018-7602 | Drupal core | RCE CWE-94 | 8.x<8.5.3 | 8.5.3 | drupal-8.5.2 | drupal-8.5.3 | auth (delete-node) | pending (PoC) |
| CVE-2020-13671 | Drupal core | upload→RCE CWE-434 | 8.9.x<8.9.9 | 8.9.9 | drupal-8.9.8 | drupal-8.9.9 | unauth? | pending (PoC) |
| CVE-2019-6341 | Drupal core | stored XSS CWE-79 | 8.6.x<8.6.13 | 8.6.13 | drupal-8.6.12 | drupal-8.6.13 | unauth | pending (PoC) |

All tarballs from `https://ftp.drupal.org/files/projects/drupal-<v>.tar.gz` (HTTP 200 verified).

---

## Appendix E — Batch 1 (Drupal) + Batch 4 (Roundcube) COMPLETED, 2026-10-11

> Continuation session. 8 remaining cases finished. Config-gated CVEs (D-023) are now **two rows each**
> (default = config-off vs enabled = config-on). Labels are ground truth (advisory + sandbox reproduction).
> All ports loopback-only; no CGI; RCE = harmless marker only.

| cve_id | product | type_cwe | affected_range | fixed_version | vuln_build | fixed_build | config_states | access_model | fixture | preconditions | repro_method | label | scenario_tags | inclusion_reason | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2018-7602 | Drupal core | RCE / CWE-94 | 7.x<7.59; 8.x<8.5.3 | 7.59/8.5.3 | drupal-7.58 (`33d29980…`) | drupal-7.59 (`292c8741…`) | 7.58/7.59 (drush 8 site-install) | auth (own cancel confirm form) | admin acct | P1 version ∧ P2 auth ∧ P3 destination unsanitised | D7 confirm-form `destination` render-array → `file/ajax` → passthru → marker | **Applicable** (7.58) / **Not Applicable a** (7.59) | — | verified #5; RCE→marker | accepted on the D7 pair (D-023); D8 not required. `CVE-2018-7602/README.md` |
| CVE-2020-13671 | Drupal core | upload→RCE / CWE-434 | 7.x<7.74; 8.8.x<8.8.11; 8.9.x<8.9.9 | 7.74/8.8.11/8.9.9 | drupal-8.9.8 | drupal-8.9.9 | **default** (article: image field png/gif/jpg only; no unsafe-extension file field) | auth (upload) | — | P1 version ∧ P2 unsafe-ext file field (absent) | `file_munge_filename` bounded | **Not Applicable b** | `config-tắt` | verified #29 | default config-off row. `CVE-2020-13671/README.md` |
| CVE-2020-13671 | Drupal core | upload→RCE / CWE-434 | 7.x<7.74; 8.8.x<8.8.11; 8.9.x<8.9.9 | 7.74/8.8.11/8.9.9 | drupal-8.9.8 | drupal-8.9.9 | **enabled** (article + file field allowing `png php`) | auth (upload) | file field with unsafe ext in allow-list | P1 version ∧ P2 unsafe-ext file field ∧ P3 name unmunged | `file_munge_filename("poc.php.png","png php")` = `poc.php.png` (8.9.8) vs `poc.php_.png` (8.9.9); 8.9.9 `file_validate` rejects | **Applicable** (8.9.8) / **Not Applicable a** (8.9.9) | `config-tắt` | verified #29 | config-on row; full RCE marker additionally needs a PHP-exec mapping (not enabled). |
| CVE-2019-6341 | Drupal core | stored XSS / CWE-79 | 7.x<7.65; 8.5.x<8.5.14; 8.6.x<8.6.13 | 7.65/8.5.14/8.6.13 | drupal-8.6.12 | drupal-8.6.13 | 8.6.12/8.6.13; registration + user_picture | unauth | invalid-UTF-8 filename + HTML body | P1 version ∧ P2 reg/picture ∧ P3 invalid-UTF-8 name | upload twice → extension-less `_0` file stored (8.6.12) vs rejected (8.6.13) | **Unresolved** (see notes) | — | verified #30 | **Rework (D-023)**: 8.6.12 stores the extension-less `_0` file, 8.6.13 rejects (RuntimeException) — clear affected/fixed difference, BUT **in-browser JS execution not obtained in chromium-1208** (sniffs `text/plain`); admin-listing route dead (escaping + MySQL 1366). Not labelled Applicable on the stored-file primitive alone. `CVE-2019-6341/README.md` |
| CVE-2021-44026 | Roundcube | SQLi / CWE-89 | <1.3.17; 1.4.x<1.4.12 | 1.3.17/1.4.12 | rc 1.4.11 (`72d1ace3…`) | rc 1.4.12 (`8fbf7251…`) | 1.4.11/1.4.12 + MariaDB + GreenMail | auth (test/test) | ≥1 contacts row | P1 version ∧ P2 auth ∧ P3 `_sort` reaches session ∧ P4 export uses it | 3-request chain → injected `SLEEP(6)` (6.07 s vs 0.05 s) | **Applicable** / **Not Applicable a** | — | verified #11 | timing signal (server-side DB exec); `CVE-2021-44026/README.md` |
| CVE-2023-5631 | Roundcube | stored XSS / CWE-79 | <1.4.15; 1.5.x<1.5.5; 1.6.x<1.6.4 | 1.4.15/1.5.5/1.6.4 | rc 1.4.11 (`72d1ace3…`) | rc 1.5.5 (`323c25b9…`) | 1.4.11/1.5.5 (+1.4.3/1.5.3 affected) | auth (reads mail) | crafted HTML email | P1 version ∧ P2 mail ∧ P3 data-URI bypass ∧ **P4 browser renders `<use data:>` (blocked)** | `data:image/s vg+xml` whitespace bypass → unsanitised SVG | **Unresolved** (see notes) | — | verified #12 | **Rework (D-023)**: server-side injection difference confirmed (affected keeps the unsanitised `<use href="data:…">`, fixed washes) but **chromium-1208 blocks `<use href="data:…">`** (hard local-scheme rule, NOT lifted by `--disable-web-security`; all other washtml sinks scriptless). Not labelled Applicable on injection alone. `CVE-2023-5631/README.md` |
| CVE-2024-37383 | Roundcube | stored XSS / CWE-79 | <1.5.7; 1.6.x<1.6.7 | 1.5.7/1.6.7 | rc 1.5.6 (`2a0da9d9…`) | rc 1.5.7 (`5b4d3f19…`) | 1.5.6/1.5.7 + MariaDB + GreenMail | auth (reads mail) | crafted HTML email | P1 version ∧ P2 mail ∧ P3 `<animate>` survives ∧ P4 victim clicks | `<animate attributeName="href " values="javascript:…">` → click → `window.__rq=1` | **Applicable** (1.5.6) / **Not Applicable a** (1.5.7) | — | verified #13 | JS execution observed in chromium-1208; `CVE-2024-37383/README.md` |
| CVE-2020-12640 | Roundcube | path traversal/LFI / CWE-22 | <1.4.4 | 1.4.4 | rc 1.4.3 (`0ee2f1b7…`) | rc 1.4.4 (`de8facfa…`) | **default** (official image: no `/installer/`) | unauth (public installer needed) | — | P1 version ∧ P2 public installer (absent) | installer absent → no impact path | **Not Applicable b** | `config-tắt` | verified #15 | default config-off row. `CVE-2020-12640/README.md` |
| CVE-2020-12640 | Roundcube | path traversal/LFI / CWE-22 | <1.4.4 | 1.4.4 | rc 1.4.3 (`0ee2f1b7…`) | rc 1.4.4 (`de8facfa…`) | **enabled** (config-on variant; as a public installer would set) | unauth (public installer) | planted `/tmp/rqp/rqp.php` + `plugins=['../../../../tmp/rqp']` | P1 version ∧ P2 installer enabled ∧ P3 fs write ∧ P4 traversal `plugins` | `include('/tmp/rqp.php')` → marker | **Applicable** (1.4.3) / **Not Applicable a** (1.4.4) | `config-tắt` | verified #15 | config-on row; marker `RQ-C1-LFI-MARKER` (1.4.3), none (1.4.4). |
| CVE-2020-12641 | Roundcube | RCE (im_convert_path) / CWE-78 | <1.4.4 | 1.4.4 | rc 1.4.3 (`0ee2f1b7…`) | rc 1.4.4 (`de8facfa…`) | **default** (official image: no `/installer/`, no `convert`) | unauth (public installer needed) | — | P1 version ∧ P2 installer (absent) | installer/convert absent → no impact path | **Not Applicable b** | `config-tắt` | verified #28 | default config-off row. `CVE-2020-12641/README.md` |
| CVE-2020-12641 | Roundcube | RCE (im_convert_path) / CWE-78 | <1.4.4 | 1.4.4 | rc 1.4.3 (`0ee2f1b7…`) | rc 1.4.4 (`de8facfa…`) | **enabled** (config-on variant) | unauth (public installer) | >240px image attachment + `im_convert_path="/nonexistent; echo … #"` | P1 version ∧ P2 installer enabled ∧ P3 config set ∧ P4 convert path | metacharacter `im_convert_path` → `rcube::exec` → marker | **Applicable** (1.4.3) / **Not Applicable a** (1.4.4) | `config-tắt` | verified #28 | config-on row; marker `RQ-C1-POC-MARKER` (1.4.3), none (1.4.4). ImageMagick not required. |

### Batch 1/4 counts (this session)
- New distinct CVEs built + labeled: **7** (CVE-2018-7602, CVE-2020-13671, CVE-2019-6341, CVE-2021-44026, CVE-2023-5631, CVE-2024-37383, CVE-2020-12640, CVE-2020-12641) — that is 8 cases; CVE-2018-7602 labelled via D7 pair.
- `n_deployments` added: D7 7.58/7.59; RC 1.4.3/1.4.4 config default+on; RC 1.4.11/1.4.12; RC 1.5.5/1.5.6/1.5.7; Drupal 8.6.12/8.6.13; Drupal 8.9.8/8.9.9.

**Running total (all sessions): 30 distinct CVEs built + labeled** (pilot 4 + lab 26). See selection-log §Batch 1/4 continuation.

---

## Appendix F — top-up 2026-10-17 (D-035/D-036)

> **Top-up, appended.** The 2 CVE IDs accepted by **D-035**; ground truth accepted by **D-036**.
> Both were built + reproduced on 2026-10-17 (`experiments/topup-2026-10-17/cases/`). Same 16-field
> schema as the main table; the 30 pre-existing rows and Appendices A–E are **unchanged**.
> Public data for these 2 IDs lives in a **separate** cohort `data/public-snapshot-2026-10-17/`
> (fetch date 2026-10-17), **not** in the frozen 2026-10-11 snapshot (D-026).
> Labels are ground truth (advisory range + sandbox reproduction), independent of any scanner
> output (D-003). Top-up numbers used below: CVE ID #31 (Joomla) and #32 (Backup Migration).

| cve_id | product | type_cwe | affected_range | fixed_version | vuln_build | fixed_build | config_states | access_model | fixture | preconditions | repro_method | label | scenario_tags | inclusion_reason | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **CVE-2023-23752** | Joomla! CMS core (API `v1/config/application`) | info disclosure / improper access check / **CWE-284** | 4.0.0–4.2.7 | 4.2.8 | `Joomla_4.2.7-Stable-Full_Package.zip` sha256 `557d7414d05de0b27900a0d94423a84b2787dfec4b252b833040becd2ccc3349`; image `rq-c1/php80-apache-joomla@sha256:91c0b3c0…` (PHP 8.0.30 / Apache 2.4.56) + `mysqli`; MariaDB 10.11 (`mariadb@sha256:7db29378…`) | `Joomla_4.2.8-Stable-Full_Package.zip` sha256 `d70ceb391d28355160d94338eaecaed2604c48f3472ee60493cf37f26f50fa44`; same image/DB | default (all 17 `webservices` plugins `enabled=1` per `installation/sql/mysql/base.sql`); **no config-off variant** (D-035 §1) | **unauth** | canary `$password`/`$secret` planted per build (`RQ-C1-CANARY-23752-DBPASS-427/428`, `…-SECRET-427/428`); DB user password = real credential | P1 version ∈ 4.0.0–4.2.7 ∧ P2 `/api/index.php` reachable (no SEF needed) ∧ P3 `plg_webservices_config` enabled (default; not directly observable unauth) | `GET /api/index.php/v1/config/application?public=true` (pages 0/20/40/60) → 200 JSON:API leaking the **real canary values**; mechanism control without `?public=true` → 401 | **Applicable** (4.2.7) | — | top-up #31 (D-035); **new product family** (first Joomla case); info-disclosure CWE; vendor advisory + official CDN package | `CVE-2023-23752/README.md`; stock web installer (`JOOMLA_INSTALLATION_DISABLE_LOCALHOST_CHECK=1`, installer-only switch); version HTTP-observable (`administrator/manifests/files/joomla.xml` + `language/en-GB/langmetadata.xml`) ⇒ no `ẩn-version`; canary also re-authenticated against the DB (fixture fact only) |
| **CVE-2023-23752** | Joomla! CMS core (API `v1/config/application`) | info disclosure / improper access check / **CWE-284** | 4.0.0–4.2.7 | 4.2.8 | `Joomla_4.2.7-Stable-Full_Package.zip` sha256 `557d7414…` (same image/DB as the row above) | `Joomla_4.2.8-Stable-Full_Package.zip` sha256 `d70ceb39…` | default (same as the affected row) | **unauth** | canary `…-427/428` (distinct per build, so a leaked value identifies the build) | P1 false (4.2.8, patched `ApiRouter` unsets the `public` query key) | same 4 `?public=true` requests → **401** `{"errors":[{"title":"Forbidden"}]}` (34 B); `grep -c RQ-C1-CANARY` = **0** in every 4.2.8 capture | **Not Applicable a** (patched build) | — | top-up #31 (D-035); clean affected/fixed control | `CVE-2023-23752/README.md`; the 401 carries `X-Powered-By: JoomlaAPI/1.0` (app-level denial, not a proxy/WAF page) |
| **CVE-2023-6553** | WP plugin Backup Migration (`backup-backup`) | RCE (PHP filter chain → `include`) / **CWE-94** | ≤ 1.3.7 | 1.3.8 | `bb-1.3.7.zip` sha256 `bdd399bf6abdb27b35fdc2e3ebbf7eda044d9d03e7c9ebe829f9da4c51e48f0c`; WP 6.7.1 (`wordpress@sha256:43693c77…`), PHP 8.2.27, Apache 2.4.62; `includes/backup-heart.php` sha256 `8796fcf2…` | `bb-1.3.8.zip` sha256 `f8c98d4696e76a09a8cf7df873ca8017131a53b702bef915bbc2966568574e44` (`backup-heart.php` sha256 `31379471…`); same WP/PHP/DB | **1.3.7 active** (baseline) | **unauth** | WP 6.7.1 install; plugin directory at `/wp-content/plugins/backup-backup/`; **no plugin setting configured** (entry point loads no `wp-load.php`); marker file `/tmp/rq-c1-poc-marker` | P1 version ≤ 1.3.7 ∧ P2 `includes/backup-heart.php` reachable by direct URL ∧ P3 PHP filter wrapper available (`iconv` + `php://filter`); **activation not required** (measured in the inactive row) | `POST /wp-content/plugins/backup-backup/includes/backup-heart.php` + `Content-Dir: php://filter/…` (5,146 chars) and the other `Content-*` headers → HTTP 200/0 B **and the marker file written** (out-of-band signal, D-015) | **Applicable** (1.3.7 active) | — | top-up #32 (D-035); unauth RCE at a plugin file level; crisp out-of-band marker signal | `CVE-2023-6553/README.md`; activation is the only variable; plugin bytes never modified (sha256 compared); body/status is **not** a success signal (the script discards its output) |
| **CVE-2023-6553** | WP plugin Backup Migration (`backup-backup`) | RCE (PHP filter chain → `include`) / **CWE-94** | ≤ 1.3.7 | 1.3.8 | `bb-1.3.7.zip` sha256 `bdd399bf…` (files present, **plugin deactivated**) | same 1.3.8 control | **1.3.7 inactive**, files present (`wp plugin deactivate backup-backup`; directory untouched) | **unauth** | same WP/PHP/DB/path as the active row | P1 version ≤ 1.3.7 ∧ P2 file reachable ∧ P3 filter wrapper available; **plugin activation is NOT a precondition** (measured, D-036) | same POST → HTTP 200/0 B **and the marker file written** | **Applicable** (1.3.7 installed, inactive) | — (measured "installed is enough"; **not** a `config-tắt` case — deactivation does not block, so there is no nhánh-b via deactivation) | top-up #32 (D-035); D-035 §2 required *measuring* active-vs-installed, not choosing it | `CVE-2023-6553/README.md`; `includes/.htaccess` ships in both packages but the image runs Apache with `AllowOverride None` → it is inert and direct PHP access is allowed by default (environment fact, recorded not "fixed"); version HTTP-observable via `readme.txt` `Stable tag` ⇒ no `ẩn-version` |
| **CVE-2023-6553** | WP plugin Backup Migration (`backup-backup`) | RCE (PHP filter chain → `include`) / **CWE-94** | ≤ 1.3.7 | 1.3.8 | same 1.3.7 build as above | `bb-1.3.8.zip` sha256 `f8c98d46…`, **active** (patched control) | **1.3.8 active** | **unauth** | same WP/PHP/DB/path | P1 false (1.3.8); the endpoint is still reachable and `filterChainFix()` rejects the value ⇒ fixed, not missing | same POST → HTTP 200, **21 B `Incorrect parameters.`** (`filterChainFix()` `die()`), marker absent; benign non-filter `Content-Dir` → 200/0 B and marker absent (the file itself still executes) | **Not Applicable a** (patched build) | — | top-up #32 (D-035); primary negative control (same environment, only the plugin version differs) | `CVE-2023-6553/README.md`; the length guard (≤256 chars) fires before the `php:` and pipe guards; the benign control shows the block is specific to the filter chain, not to a missing file |

### Appendix F counts (this top-up)

- New distinct CVE IDs: **2** → total **32** (30 resolved {Applicable/NotApplicable} + 2 Unresolved: CVE-2023-5631, CVE-2019-6341).
- New cases: **5** (23752 × 2 builds; 6553 × 3 states) → total **69** cases.
- New labels: **Applicable 3** (23752@4.2.7, 6553@1.3.7-active, 6553@1.3.7-inactive); **Not Applicable a 2** (23752@4.2.8, 6553@1.3.8).
- Aggregate after this appendix: Applicable **31**, Not Applicable **36** (branch a 30, branch b 6), Unresolved **2** → **69**.
- `n_deployments` added: Joomla 4.2.7/4.2.8 (one image, two builds) + 3 WP-plugin activation states on one WP 6.7.1 deployment.
- Raw artifacts: `experiments/topup-2026-10-17/cases/<CVE>/artifacts/` (+ `_stack/` for the compose stack); index in `cases/README.md`, hashes in `cases/artifact-manifest.sha256`.
