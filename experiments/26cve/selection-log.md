# Selection log — Batch 0 (anti-cherry-pick)

> Date: 2026-10-10. Per `notes/lab-spec-26-cve-2026-10-10.md` §8.
> Batch 0 = the 5 de-risk cases from §5 (rows #14, #16, #17, #18, #26 of the 26-CVE queue).
> A case removed after building is recorded with its cause; **no replacement case is
> swapped in "to look better".** Selection predates the build (chosen 2026-10-07 in the
> verified list; Batch-0 grouping set in the spec).

## Sources

- CVE list + advisory ranges: `notes/cve-verification-2026-10-07.md` (30 verified IDs).
- Batch-0 grouping + risk flags: `notes/lab-spec-26-cve-2026-10-10.md` §4/#14,#16,#17,#18,#26 and §6.
- Advisories opened during this build (URLs in each case README): CVE record / NVD /
  WPScan / RIPSTECH+SonicWall (Sonar) / ZDI / WordPress security release / Ubuntu security tracker.

## Per-case log

| CVE | Source/date selected | Include reason | Build outcome | Artifact root |
|---|---|---|---|---|
| CVE-2019-8942 | verified list #17 (2026-10-07); Batch 0 (spec) | WP-core RCE with a real precondition (**author**) flagged for de-risk; public PoC (RIPSTECH + Metasploit). | ✅ built + reproduced | `CVE-2019-8942/` |
| CVE-2021-29447 | verified list #18 (2026-10-07); Batch 0 (spec) | WP-core XXE requiring **PHP 8** (runtime precondition) flagged for de-risk; public PoC. | ✅ built + reproduced | `CVE-2021-29447/` |
| CVE-2022-21661 | verified list #19 (2026-10-07); Batch 0 (spec) | WP-core SQLi requiring a **plugin/theme fixture** flagged for de-risk; public PoC (ZDI). | ✅ built + reproduced (fixture = Ele Custom Skin 3.1.3) | `CVE-2022-21661/` |
| CVE-2021-24284 | verified list #26 (2026-10-07); Batch 0 (spec) | WP-plugin upload→RCE; spec flagged the **discontinued/removed download** as the top risk → Batch 0. | ❌ **feasibility failure** — no trustworthy source for 3.0.1 | `CVE-2021-24284/` |
| CVE-2021-23017 | verified list #27 (2026-10-07); Batch 0 (spec §6) | Special **already-patched-via-backport** case; needed for the negative/`Unknown` scenario. | ✅ built + labeled (no exploitation) | `CVE-2021-23017/` |

## Exclusions / failures (with cause — not replaced)

- **CVE-2021-24284 — excluded from reproduction (feasibility failure).** The official
  wordpress.org CDN and SVN are 404, the plugin API is "not found", there is **no
  Wayback capture**, and no GitHub mirror hosts the vulnerable zip; the only remaining
  sources are paid/CodeCanyon or **"nulled" resale** sites (untrustworthy). Per the
  spec, recorded as a feasibility failure rather than fabricating a download. Label =
  **Unresolved** (not `Not Applicable`). See `CVE-2021-24284/artifacts/source-search.txt`.
  **A researcher decision is required** on how to fill this slot (drop, substitute a
  downloadable WP-plugin upload CVE already in the list e.g. CVE-2020-25213 /
  CVE-2020-35489, or accept a synthetic fixture — the last is discouraged).

No other Batch-0 case was dropped, and no case was swapped in.

## Counting (protocol R4 — distinct CVEs vs cases)

| Metric | Batch 0 |
|---|---|
| `n_unique_cves` | **5** (CVE-2019-8942, CVE-2021-29447, CVE-2022-21661, CVE-2021-24284, CVE-2021-23017) |
| `n_deployments` (version × config) | **7** (WP 5.0.0, 5.0.1, 5.7.0-php8, 5.7.1-php8, 5.8.2, 5.8.3, nginx-1.18.0-jammy) |
| `n_cases` (product, version, config, CVE) | **7** (3 WP CVEs × {affected, fixed} = 6, + nginx = 1) |
| `n_cases_with_label` | **7** (5.0.0→Applicable, 5.0.1→NotApplicable, 5.7.0→Applicable, 5.7.1→NotApplicable, 5.8.2→Applicable, 5.8.3→NotApplicable, nginx→NotApplicable) |
| `n_observation_conditions` | **7** |

Note: each of the three WP CVEs contributes an **affected** AND a **fixed** case
(6 labeled cases); nginx contributes 1 → **7 labeled cases**; Kaswara contributes
**0** (Unresolved — no build).

## Open items for researcher (Batch 0)

1. Kaswara slot disposition (see above).
2. CVE-2022-21661: is the third-party fixture plugin part of the case identity?
3. nginx: confirm the `-6ubuntu14.21`-in-jammy-container substitution for `-6ubuntu9`
   is acceptable (semantics unchanged; the lab VM is 24.04, native nginx out of range).

---

# Selection log — Replacement + Batch 2 (2026-10-10)

## Replacement for the failed CVE-2021-24284 (researcher decision, Task 1)

Mini-log (candidates considered; chosen by the pre-registered criteria, **not** by method score):

| Candidate | Type/CWE | Source availability | PoC | Verdict |
|---|---|---|---|---|
| **CVE-2023-5798** (Assistant <1.4.4) | Editor+ **SSRF (CWE-918)** | ✅ `assistant.{1.4.3,1.4.4}.zip` both HTTP 200 | ✅ WPScan PoC (`fl_asst_image_proxy&url=`) | **CHOSEN** — new CWE (CME under-represented), WP plugin (same family as Kaswara), crisp out-of-band signal |
| CVE-2022-1398 (External Media without Import ≤1.1.2) | subscriber+ blind SSRF (CWE-918) | ⚠ fixed `1.1.3.zip` 404 (plugin closed) | ✅ WPScan | Rejected — fixed build unavailable (Kaswara-class problem) + blind SSRF weaker signal |
| CVE-2021-38312 (Gutenberg Template Library/Redux ≤4.2.11) | contributor+ authorization (CWE-863) | ✅ 4.2.11 + 4.2.13 both 200 | ✅ Rapid7 | Rejected — impact (install plugin via REST) fuzzier to observe; SSRF adds a cleaner new CWE |
| CVE-2021-25032 (PublishPress Capabilities <2.3.1) | unauth option update (CWE-862) | ❌ affected `2.3.0.zip` 404 | ✅ WPScan | Rejected — affected build undownloadable |

Chosen: **CVE-2023-5798** (see `CVE-2023-5798/README.md`). Built + reproduced: 1.4.3 SSRF → listener hit; 1.4.4 blocked.

## Batch 2 per-case log (rows #7–#13)

| CVE | Source/date | Include reason | Outcome | Artifact |
|---|---|---|---|---|
| CVE-2020-25213 | verified list #7 | CISA-KEV unauth upload→RCE | ✅ Applicable/NotApplicable-a (fixed 8.0.6; **6.9 zip gone**) | `CVE-2020-25213/` |
| CVE-2024-28000 | verified list #8 | unauth privilege escalation; hash condition | ✅ Applicable/NA-a (hash via DB ground truth; brute force out of budget) | `CVE-2024-28000/` |
| CVE-2023-32243 | verified list #10 | unauth account takeover | ✅ Applicable/NA-a | `CVE-2023-32243/` |
| CVE-2023-3460 | verified list #22 | unauth registration priv-esc | ✅ Applicable/NA-a | `CVE-2023-3460/` |
| CVE-2019-10692 | verified list #24 | unauth REST SQLi | ✅ Applicable/NA-a | `CVE-2019-10692/` |
| **CVE-2024-27956** | verified list #25 | unauth SQLi | ❌ **FEASIBILITY FAILURE** — plugin removed from wordpress.org (api "not found", SVN 404, all version zips 404) | `CVE-2024-27956/` |
| **CVE-2020-35489** | verified list #23 | upload→RCE | ⚠️ **Unresolved** — independent analyses report non-reproducibility without a special config; did not fabricate one | `CVE-2020-35489/` |

## Failures / STOP condition

- **CVE-2024-27956** — feasibility failure (no source). Distinct-CVE count would fall below 30.
- **CVE-2020-35489** — Unresolved (not reproduced).
- **CVE-2021-24284** — previously a feasibility failure; replaced by CVE-2023-5798.

Per the work instruction, the lab **STOPPED** on the below-30 condition so the researcher can top up.

## Running counts (through replacement + Batch 2)

| Metric | Value |
|---|---|
| `n_unique_cves` built+labeled (all batches so far) | **16** (pilot 4 + Batch 0 4 + Batch 3 3 + replacement 1 + Batch 2 5 → but pilot CVEs are the 4 already reproduced; distinct built by lab sessions = 12; plus 4 pilot) |
| Batch 2 `n_unique_cves` | 5 built + 1 feasibility failure + 1 unresolved |
| Replacement | 1 built |
| Remaining NOT built | Batch 1 (6) + Batch 4 (5) = **11** |

> Distinct-CVE accounting for the ≥30 target: 30 verified − CVE-2021-24284 (replaced by CVE-2023-5798) = 29 original
> + 1 replacement = 30 nominally; but **CVE-2024-27956 and CVE-2020-35489 are failing/unresolved**, so the
> achievable total is **28 unless the researcher tops up**. Batches 1 and 4 are unbuilt.

---

# Selection log — Batch 1, Batch 4, and 2 replacements (2026-10-10, continuation)

## Replacement CVEs (Task B)

**R-A = CVE-2021-24917** (WPS Hide Login ≤1.9, CWE-863) — replaces CVE-2024-27956.
_Mini-log_: considered **CVE-2022-1398** (External Media without Import, SSRF — rejected: fixed `1.1.3.zip` 404),
**CVE-2021-25032** (PublishPress Capabilities — rejected: affected `2.3.0.zip` 404), **CVE-2021-24917** (chosen:
both versions downloadable, clear referer-bypass PoC, simple unauth repro).
Built + reproduced: 1.9 leaks the secret login URL `rqsecret`; 1.9.1 → `?404`.

**R-B = CVE-2023-28121** (WooCommerce Payments <5.6.2, CWE-287) — replaces CVE-2020-35489.
_Mini-log_: considered **CVE-2024-1071** (Ultimate Member SQLi — attempted, but the "custom usermeta table"
sync could not be made to expose the vulnerable path; not reproduced), **CVE-2024-4704** (CF7 open redirect —
no working PoC endpoint found in testing; rejected), **CVE-2023-28121** (chosen: documented PoC, both versions +
WooCommerce downloadable, reproduced cleanly).
Built + reproduced: 5.6.1 → REST `POST /wp/v2/users` with `X-WCPAY-PLATFORM-CHECKOUT-USER: 1` → **201 admin**; 5.6.2 → 401.

## Batch 1 (Apache + Drupal) — rows #1–#6

| CVE | Outcome | Note |
|---|---|---|
| CVE-2021-42013 | ✅ **Applicable / NA-a** | httpd 2.4.50 double-encoded `%%32%65` traversal → marker; 2.4.51 → 400 |
| CVE-2014-3704 | ❌ **BLOCKED (not built)** | no affected Drupal 7.x image is pullable (manifest v1 + Hub rate limit) |
| CVE-2018-7600 | ❌ **BLOCKED** | `drupal:7.5x/8.5.x` images unpullable |
| CVE-2018-7602 | ❌ **BLOCKED** | `drupal:7.5x` images unpullable |
| CVE-2020-13671 | ❌ **BLOCKED** | `drupal:8.8.x` images unpullable |
| CVE-2019-6341 | ❌ **BLOCKED** | `drupal:7.6x/8.6.13` images unpullable |

**Blocker (NEW, environmental):** the required Drupal images use the **deprecated Docker manifest v1**, which
containerd ≥2.1 (Docker 29) refuses; additionally the VM's **Docker Hub anonymous pull rate limit is exhausted**
(skopeo conversion also hit `toomanyrequests`). Workaround: build custom images from `ftp.drupal.org` tarballs
(all verified HTTP 200) onto the already-local `drupal:8.6.9-apache` base — feasible but not completed in this session.

## Batch 4 (Roundcube) — rows #21–#25

Stack built (`~/batch4-lab`, 8 RC instances 1.4.3/1.4.4/1.4.11/1.4.12/1.5.3/1.5.5/1.5.6/1.5.7 + MariaDB + GreenMail), all loopback.

| CVE | Outcome | Note |
|---|---|---|
| CVE-2020-12640 | ⚠️ **config-gated / not reproduced** | official image has **no `/installer/`** → LFI path blocked (nhánh-b style); not labeled |
| CVE-2020-12641 | ⚠️ **config-gated / not reproduced** | same installer dependency; no `convert`/imagick in image |
| CVE-2021-44026 | ⏳ **not completed** | authenticated SQLi chain (needs session / XSS chain) |
| CVE-2023-5631 | ⏳ **not completed** | SVG XSS harness attempted; payload did not execute in headless check |
| CVE-2024-37383 | ⏳ **not completed** | SVG `animate onbegin`/`href ` XSS harness attempted; did not execute |

## Final distinct-CVE accounting

- **Built + labeled: 20** — pilot 4 (41773, 6340, 10924, 12625) + lab 16 (8942, 29447, 21661, 23017; 2017-1001000, 2023-2745, 2015-3440; 10692, 25213, 32243, 3460, 28000; 5798, 24917, 28121; 42013).
- **Replaced/dropped: 3** (24284→5798; 27956→24917; 35489→28121).
- **Not built: 10** (Batch 1 Drupal 5 + Batch 4 5).
- **Target ≥30:** currently **20/30**. Batch 1 (Drupal) is blocked by image availability; Batch 4 needs the XSS/SQLi harness.

---

# Selection log — Drupal tarball builds (D-022) + Roundcube status (2026-10-10)

## Drupal (Batch 1) — tarball deployment on the local `drupal@sha256:d6073e2f…` base

All 10 instances built and site-installed (drush 9 for 8.5/8.6, drush 9 for 8.9, D7 web installer):

| CVE | pair | status | label |
|---|---|---|---|
| CVE-2014-3704 | 7.31 / 7.32 | ✅ built + reproduced | Applicable / NA-a |
| CVE-2018-7600 | 8.5.0 / 8.5.1 | ✅ built + reproduced | Applicable / NA-a |
| CVE-2018-7602 | 8.5.2 / 8.5.3 | ⏳ instances built; PoC not completed | pending |
| CVE-2020-13671 | 8.9.8 / 8.9.9 | ⏳ instances built; PoC not completed | pending |
| CVE-2019-6341 | 8.6.12 / 8.6.13 | ⏳ instances built; PoC not completed | pending |

Tarball URLs + sha256 recorded in the per-case READMEs / registry (ftp.drupal.org).
Workarounds recorded: (a) Drupal 8.5.x MariaDB ≥10.2 schema conflict → one-line core patch
(`Schema.php`: `if`→`elseif` for `varchar_ascii`); (b) Drupal 7 needs a mysql client absent in the EOL
stretch base → PDO web installer (`scripts/install-d7.py`); (c) drush 10 requires PHP 7.3 (base is 7.2)
→ drush 9 for 8.9.x.

## Roundcube (Batch 4) — not completed

Stack built (`~/batch4-lab`, 8 RC instances 1.4.3/1.4.4/1.4.11/1.4.12/1.5.3/1.5.5/1.5.6/1.5.7 + MariaDB +
GreenMail), SMTP delivery verified, headless-Chromium harness written. Not completed:
- **CVE-2020-12640**: installer absent in the official image → default = **Not Applicable nhánh b**
  (config-gated); a positive control requires restoring `/installer/` from the RC release tarball.
- **CVE-2020-12641**: same installer dependency + no ImageMagick in the image → default **Not Applicable nhánh b**.
- **CVE-2021-44026**: authenticated SQLi chain not completed.
- **CVE-2023-5631 / CVE-2024-37383**: SVG payloads crafted (from PT-ESC/CrowdStrike write-ups) did not
  execute in the harness; needs the exact version-specific sanitizer bypass.

## Counts
- **Built + labeled: 22** (adds CVE-2014-3704, CVE-2018-7600 to the prior 20).
- **Pending: 8** (Drupal 3 + Roundcube 5). Target ≥30.

---

# Selection log — Batch 1 (Drupal) + Batch 4 (Roundcube) completed (2026-10-11)

## Per-case log (8 remaining cases)
| CVE | Source/date | Include reason | Outcome | Artifact |
|---|---|---|---|---|
| CVE-2018-7602 | verified #5 | Drupal core RCE (Drupalgeddon3); authenticated confirm-form render-array injection | ✅ **Applicable / NA-a** (D7 7.58/7.59) | `CVE-2018-7602/` |
| CVE-2020-13671 | verified #29 | Drupal core filename-sanitisation → upload RCE | ✅ **Not Applicable b** (default) + variant diff (`file_munge_filename`); config-conditional | `CVE-2020-13671/` |
| CVE-2019-6341 | verified #30 | Drupal core stored XSS via upload (invalid-UTF-8 filename) | ✅ **Applicable / NA-a** (8.6.12/8.6.13) | `CVE-2019-6341/` |
| CVE-2021-44026 | verified #11 | Roundcube authenticated SQLi (search) | ✅ **Applicable / NA-a** (1.4.11/1.4.12) | `CVE-2021-44026/` |
| CVE-2023-5631 | verified #12 | Roundcube stored XSS (SVG data-URI) | ⚠️ **Applicable (injection) / NA-a**; browser `<use data:>` block → caveat/FLAG | `CVE-2023-5631/` |
| CVE-2024-37383 | verified #13 | Roundcube stored XSS (SVG `<animate>`) | ✅ **Applicable / NA-a** (1.5.6/1.5.7; JS executed) | `CVE-2024-37383/` |
| CVE-2020-12640 | verified #15 | Roundcube LFI via `plugins` option | ✅ **Not Applicable b** (default, no installer) + positive control | `CVE-2020-12640/` |
| CVE-2020-12641 | verified #28 | Roundcube command injection via `im_convert_path` | ✅ **Not Applicable b** (default) + positive control | `CVE-2020-12641/` |

## Deviations / flags (not self-modified)
1. **CVE-2018-7602** labelled on the **Drupal 7 7.58/7.59** pair, not the pre-built 8.5.2/8.5.3 pair. On D8 the D7 `/file/ajax` trigger route does not exist; the D8 vector (`ManagedFile::element_parents` + `RequestSanitizer::checkDestination`, both fixed in 8.5.3) was not completed. The D8 pair remains built (8905/8906), PoC pending. **Researcher decision needed.**
2. **CVE-2023-5631**: server-side injection difference is confirmed (affected emits the attacker's unsanitised SVG data-URI; fixed washes it), but **chromium-1208 blocks `<use href="data:…">`** (cross-origin), so no in-browser JS execution was observed. Labelled Applicable on the injection with an explicit caveat / FLAG (possible nhánh-b / Unresolved reading). 1.4.15 image was unpullable (Docker Hub 429) → used 1.5.5 (identical fix commit) as the fixed control, plus 1.4.3/1.4.11/1.5.3 verified affected.
3. **CVE-2019-6341**: affected version still answers HTTP 500 for the upload (Drupal error from the invalid UTF-8) — success is the **stored file**, not the status (D-015). The stored `_0` file did not execute the inline `<script>` in chromium-1208 (no Content-Type + GIF prefix → classified as image); the affected/fixed difference (stored vs rejected) is unambiguous.
4. **CVE-2020-13671**: config-conditional ("executed if the server configuration allows"). The default standard deployment has no file field permitting an unsafe extension → **nhánh b**. Sink difference (`file_munge_filename`) reproduced; the full RCE marker would additionally need a PHP-exec mapping for the crafted name (not enabled — safety boundary).
5. **CVE-2020-12640 / 12641**: both require a **public Roundcube installer** to set the attacker-controlled config. Official images ship no `/installer/` → default = **nhánh b**; positive controls (config-on variants) reproduced on 1.4.3 and neutralised on 1.4.4. ImageMagick was *not* required for 12641 (shell metacharacters run regardless).
6. **Drupal 7.31/7.32** (CVE-2014-3704 pair) predate PHP 7.2 support → the web installer left the `placeholder-for-uid-1` row; for the 7.58/7.59 pair drush 8 `site-install` created the real admin. A `mysql` client shim (`mysql-shim.php`) was needed for drush's DB checks on the EOL base image.

## Running counts after this session
| Metric | Value |
|---|---|
| `n_unique_cves` built + labeled (all sessions) | **30** (pilot 4 + lab 26) |
| dropped/replaced (recorded) | 3 (24284→5798; 27956→24917; 35489→28121) |
| new deployments this session | D7 7.58/7.59; RC 1.4.3/1.4.4 (default + config-on); RC 1.4.11/1.4.12; RC 1.5.5/1.5.6/1.5.7; Drupal 8.6.12/8.6.13; Drupal 8.9.8/8.9.9 |

Target **≥30 distinct CVE IDs** (D-010): **met (30/30)**.

---

# Rework of the two XSS cases (2026-10-11, D-023)
- **CVE-2023-5631**: in-browser execution **unobtainable in chromium-1208**. The whitespace/`data:image/svg`
  bypass only enables `<use href="data:…">`, which Chromium blocks (hard SVG `<use>` local-scheme rule, not
  lifted by `--disable-web-security`); all other whitelisted sinks are scriptless. → relabelled **Unresolved**
  (was "Applicable (injection)"). Server-side affected/fixed difference documented.
- **CVE-2019-6341**: in-browser execution **not obtained**. 8.6.12 stores the extension-less `_0` file vs
  8.6.13 rejects (clean difference) but Chromium sniffs `_0` as `text/plain`, `<object type=text/html>` hints
  are ignored, and the admin-listing route is dead (escaping + MySQL 1366). → relabelled **Unresolved**.
- **D-023 splits applied**: CVE-2020-13671, CVE-2020-12640, CVE-2020-12641 now each appear as **two registry
  rows** (default config-off = Not Applicable nhánh b; enabled config-on = Applicable / NA-a).
- Accepted per D-023: CVE-2018-7602 on the Drupal 7 7.58/7.59 pair; CVE-2023-5631 fixed = 1.5.5 for 1.4.15.
- **Distinct-CVE count**: 28 labelled {Applicable/NotApplicable} + 2 Unresolved (5631, 6341). A 2-CVE top-up
  is required to restore ≥30 unless the researcher accepts the primitive-level evidence for these two.

---

# Top-up (2026-10-17, D-035/D-036)

> Appended 2026-10-17. 2 CVE IDs added to the benchmark **after** the 30-ID list was complete
> (28 resolved + 2 Unresolved). Scope/lab-plan rulings: **D-035**; ground truth: **D-036**.
> Labels were accepted from sandbox reproduction, not from scanner output. Nothing in the
> earlier sections of this log is changed.

## Why a top-up (state of the list before it)

Per **D-024** the two XSS cases stay `Unresolved` (manual reproduction, not top-up'd), so the
labelled count was **28** — below the **≥30** scale required by **D-010**. Adding 2 IDs restores
32 distinct IDs (30 resolved + 2 Unresolved) without relabelling or swapping the XSS cases.

## Candidates considered — mini-log

The candidate set agreed for the top-up was **{CVE-2023-23752, CVE-2023-6553}** (D-035). Both were
verified at advisory + download level first (`notes/cve-verification-topup-2026-10-17.md`) and only
then built.

| Candidate | Type/CWE | Why it was a candidate | Source / build availability | Signal | Verdict |
|---|---|---|---|---|---|
| **CVE-2023-23752** (Joomla! CMS 4.0.0–4.2.7) | info disclosure / improper access check, **CWE-284** | **New product family** (first Joomla case in the benchmark — previously Apache, Drupal, WordPress, Roundcube, nginx only); a *disclosure* outcome rather than another RCE/XSS; the CWE-200-style "impact = leaked value" shape | vendor advisory HTTP 200; both official CDN packages HTTP 200 + sha256; NVD + CVE.org agree on 4.0.0–4.2.7 → 4.2.8 | crisp: the **canary config value** must appear in the body (D-035 §4 explicitly forbids counting key names or a bare 200) | **CHOSEN** — built + reproduced |
| **CVE-2023-6553** (WP plugin Backup Migration ≤ 1.3.7) | unauth RCE, **CWE-94** | mixes the benchmark's largest family (WP plugins) but at a *file-level* entry point that needs no activation; adds the "installed vs active" question the protocol wants measured, not assumed | both plugins from the official wordpress.org directory (200 + sha256); **WPScan 403 / Wordfence 202** → range from NVD + CVE.org, fixed version confirmed from the 1.3.8 package diff | crisp: out-of-band **marker file** (D-015), because the script discards its own output | **CHOSEN** — built + reproduced |

**No rejected shortlist is recorded here.** No ranked list of alternative candidates was evaluated
in the workspace for this top-up; if additional candidates were discussed outside the workspace
they are not documented and are deliberately **not reconstructed** here. The reasons above are the
recorded inclusion criteria, in this order: (1) a gap in product/CWE coverage, (2) trustworthy,
hash-verifiable affected **and** fixed sources, (3) a crisp, non-status-based success signal,
(4) compatibility with the level-2 label definition (D-008).

**Explicitly not the reason:** neither case was added "to look better". Note the honest
consequence, which is recorded rather than hidden: **both** new cases expose their version over HTTP
(`joomla.xml` / `langmetadata.xml`; plugin `readme.txt` `Stable tag`), so they add 2 cases with an
easy E5 observation to a benchmark where many cases have no version observation (D-031). This
shifts the difficulty mix in the *easier* direction and is a fact about the additions, not a
selection criterion.

## Reproduction outcome + labels (D-036)

| Case | Observed | Label |
|---|---|---|
| CVE-2023-23752 @ 4.2.7 | `GET /api/index.php/v1/config/application?public=true` → 200 JSON:API; real canary `$password` + `$secret` values leaked (65 keys over 4 pages); control without `?public=true` → 401 | **Applicable** |
| CVE-2023-23752 @ 4.2.8 | same 4 requests → 401 `{"errors":[{"title":"Forbidden"}]}`; canary absent | **Not Applicable a** |
| CVE-2023-6553 @ 1.3.7 **active** | POST with `Content-Dir: php://filter/…` → 200/0 B **and marker file written** | **Applicable** |
| CVE-2023-6553 @ 1.3.7 **inactive** (files present) | same POST → marker written | **Applicable** |
| CVE-2023-6553 @ 1.3.8 | 200, 21 B `Incorrect parameters.` (`filterChainFix`), marker absent; benign non-filter control still executes the file | **Not Applicable a** |

Artifacts: `experiments/topup-2026-10-17/cases/` (per-case `README.md`, raw captures, `artifact-manifest.sha256`, `_stack/`).

## Findings that change how this CVE must be treated downstream

1. **"Installed is enough" (CVE-2023-6553, measured).** Deactivating the plugin does **not** block
   the entry point: `includes/backup-heart.php` is a standalone file that loads no `wp-load.php`, so
   it answers by direct URL whether or not WordPress loads the plugin. D-035 §2 required measuring
   this rather than choosing it; the measurement came out positive. Consequences:
   - the 1.3.7 **inactive** state is also **Applicable** (a third case, not a negative control);
   - there is **no `config-tắt` / nhánh-b** for this CVE via deactivation — a negative can only come
     from the **patched build** (nhánh a) or from the files being absent;
   - a mapping that treated "plugin active" as a path precondition would be **wrong** for this CVE
     (it would manufacture a nhánh-b that the deployment does not have).
2. **`AllowOverride None` on the WP image (environment fact).** The plugin ships
   `includes/.htaccess` (`Require all granted` for `*.php`, `RewriteEngine off`), but the image's
   Apache ignores `.htaccess`, so direct access to `includes/*.php` is **allowed by default**.
   Recorded as an environment property, **not** "fixed" and not tuned to make the PoC work. A
   deployment that blocks direct PHP access under `wp-content/plugins/` would be a *different*
   configuration and would have to be measured, not assumed (it is also the reason the reachability
   precondition is a real precondition rather than a formality).
3. **Joomla had no config-off variant** (D-035 §1): the default configuration has all 17
   `webservices` plugins enabled, and a config-off instance alone could not justify a negative
   (the defect sits in the shared API router). So both 23752 rows are default-configuration rows.
4. **23752's lab deviation** (recorded, installer-only): `JOOMLA_INSTALLATION_DISABLE_LOCALHOST_CHECK=1`
   was needed because the stock installer refuses a non-`localhost` DB host. It does not touch the
   API path.

## Running counts after the top-up

| Metric | Value |
|---|---|
| `n_unique_cves` (all sessions) | **32** = 30 resolved {Applicable/NotApplicable} + 2 Unresolved (CVE-2023-5631, CVE-2019-6341) |
| new distinct CVE IDs this step | **2** (CVE-2023-23752, CVE-2023-6553) |
| `n_cases` | **69** (64 before + 5) |
| labels | Applicable **31**, Not Applicable **36** (branch a 30, branch b 6), Unresolved **2** |
| dropped/replaced | unchanged (24284→5798; 27956→24917; 35489→28121) |
