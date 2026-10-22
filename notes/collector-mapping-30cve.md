# Collector/mapping 32 CVE (30 CVE gốc + 2 CVE top-up) — bảng điền + sửa logic (RQ-C1)

> Ngày: 2026-10-14. Điền (bước 1): engineer (DeepSeek V4.1 Flash); **rà + phán quyết + khoá (bước 2): researcher (DeepSeek V4 Pro)**.
> Trạng thái: **ĐÃ KHÓA 2026-10-14 (bước 2, D-030)** — sửa logic theo `reviews/Review_buoc2_mapping_phanquyet_2026-10-14.md`
> (G1–G7: tách B/P_i, probe version trung lập, không 403/404→False, không đường NOT(), XSS=execution, cổng runtime).
> **Amendment 2026-10-17 (top-up D-035/D-036 + rulings `reviews/Review_mapping_topup_phanquyet_2026-10-17.md`):**
> merge 2 block top-up (CVE-2023-23752, CVE-2023-6553) vào cuối danh sách ⇒ file này giờ là **mapping 32 CVE**
> (30 CVE gốc + 2 CVE thêm sau V1/V2); 4 probe được nâng `pending` → `verified` theo capture 2026-10-17; path của
> 23752 rút về `[p_config_object_readable]` và path của 6553 rút về `[p_plugin_files_present]` (phán quyết #3/#6).
> **Freeze bản 32-CVE (hash mới) = D-037 — CHƯA thực hiện tại thời điểm ghi amendment này.**
> **Amendment 2026-10-15 (D-032 ACCEPTED):** hạ `CVE-2017-1001000.probe_rest_root` verified→pending (capture chỉ ghi status,
> thiếu body JSON 'routes'). Hash mới ghi ở D-032; hash gốc D-030 = `f266673ee3f1b2d6ae14b0ac2357a550d63a4013b4eb7f1e8676509248d7fbd1` (để đối chiếu).
> **Amendment 2026-10-15 (D-033 ACCEPTED):** sửa request 2 probe cho khớp lab plain-permalink + namespace: `probe_rest_root`
> → `GET /?rest_route=/`; `probe_two_fa_route` → `POST /?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding`. Hash mới ghi ở D-033.
> **Amendment 2026-10-16 (D-034 ACCEPTED):** nâng 4 probe verified (rest_root, two_fa_route, 3460 readme + register_form) nhờ capture V2;
> đánh dấu 1001000 + 3460 `used_for_signal_development`. Hash mới ghi ở D-034.
> Theo `notes/collector-mapping-spec-2026-10-11.md` (§2 schema, §3 R1–R5, §4 operational, §5 development use).
> Nguồn điền: `data/public-snapshot/<CVE>/{cpe.json,nvd.json,advisory*.html}` (snapshot 2026-10-11, D-026),
> cohort thứ hai `data/public-snapshot-2026-10-17/<CVE>/{cpe.json,nvd.json,advisory*}` (top-up 2026-10-17, D-035) cho 2 CVE mới,
> `experiments/26cve/registry.md` (Appendix E + Appendix F + running-total = trạng thái cuối), `experiments/26cve/selection-log.md`,
> và per-case `README.md` + `artifacts/` (pilot 4: `experiments/pilot-3cve/`, `experiments/reproduce-cve-2021-41773/`,
> top-up 2: `experiments/topup-2026-10-17/cases/`).
> **Không** sửa snapshot/registry/selection-log/spec/decision; không chạy lab; không đổi nhãn.

## Legend — `validation.status` (D-028 R3, hai tầng)

- **`verified`** — đã điền mapping VÀ tồn tại artifact HTTP **thật** trong `artifacts/` (capture của chính request đó)
  khớp `interpret.true_when`/`false_when` cho **toàn bộ trạng thái đối chứng yêu cầu** (affected + fixed, hoặc config-on +
  config-off), và access model đã rõ. Probe xác nhận **trạng thái predicate**, KHÔNG xác nhận nhãn CVE.
- **`pending`** — mapping đã trích được nhưng artifact HTTP khớp còn thiếu, hoặc chỉ phủ một trạng thái đối chứng.
- **`needs_control`** — case **không có tín hiệu HTTP** cho điều kiện đó (version bị ẩn, package revision không lên header,
  config chỉ phân biệt được bằng chính request khai thác…) → để `observable: false`, KHÔNG tạo probe giả.

**Quy ước bổ sung so với §2 (ghi rõ để researcher kiểm):**

- Mỗi entry `ranges_by_source.*` có thêm khoá **`literal:`** = trích nguyên văn dải/affirmed-version đọc được từ artifact
  (yêu cầu của đề bài "quote the literal range text"); `field:` ghi path JSON/HTML cụ thể đã đọc.
- Condition có thêm `observable:` (bool) và (khi cần) `evidence_ref:`. `observable: false` ⇒ **không** có probe *khẳng định*
  cho nó; ngoại lệ duy nhất là **probe âm** (negative-observability: xác nhận "không quan sát được" — vd role qua login,
  version plugin ẩn) có thể `maps_to` condition `observable: false` và ghi rõ đó là probe âm.
- Condition có thêm `kind:` = `build` (product/version/patch/sink — thuộc `B`, **KHÔNG** nằm trong `paths.all_of`) hoặc
  `precondition` (config/access/fixture — thuộc `P_i`, **NẰM** trong `paths.all_of`). `paths.all_of` chỉ chứa `kind: precondition`.
  Version/range/patch/sink do luật method tính từ `ranges_by_source` + probe E5; KHÔNG đưa vào path (phán quyết G1).
- Probe version (E5) `maps_to` condition `p_version_observed` (kind: build); `interpret` chỉ quyết **có quan sát được
  version string hay không** (ghi giá trị V), KHÔNG chứa cutoff affected; khớp V với dải là việc của từng method theo nguồn (G2).
- `false_when` chỉ được phép là **tín hiệu vắng mặt dương, cụ thể**; 403/404 trần hoặc "không thấy feature/form/asset"
  → chuyển sang `ambiguity_when` (Unknown) (G3).
- **Cổng runtime (G7):** `interpret.{true_when,false_when}` chỉ được đánh giá thành True/False ở runtime khi
  `validation.status == verified`; `pending`/`needs_control` → predicate trả Unknown (bất kể response) tới khi có artifact đối chứng.
- Neo `path` dùng `scope_ref` trỏ tới advisory/CVE record tương ứng.
- Probe feature/config (E6) cần **cả hai cực** (bật + tắt) trong capture thô mới đủ `verified`; nếu chỉ một cực → `pending`.
- Probe POST có thêm khoá `request.body` (ngoài `method/path/headers` của §2) để predicate kiểm được đúng tham số; các probe GET/HEAD không có khoá này.

**Bằng chứng HTTP "thật" dùng để chấm `verified` (chỉ các file này, và chỉ ở các CVE tương ứng):**

- `experiments/26cve/_batch0-stack/artifacts/http-observations.txt` (WP 5.0.0/5.0.1, 5.7.0-php8/5.7.1-php8, 5.8.2/5.8.3, nginx)
- `experiments/26cve/_batch1-stack/artifacts/http-observations.txt` (Drupal 7.31/7.32, 8.5.0/8.5.1/8.5.2/8.5.3, 8.9.8/8.9.9, 8.6.12/8.6.13)
- `experiments/26cve/_batch3-stack/artifacts/http-observations.txt` (WP 4.7.1/4.7.2, 6.2.0/6.2.1, 4.2-src/4.2.1)
- `experiments/26cve/CVE-2021-23017/artifacts/23017-nginx-observable-vs-truth.txt` (1 trạng thái)
- `experiments/26cve/CVE-2021-42013/artifacts/42013-repro.txt` (Server header + kết quả request, 2.4.50/2.4.51)
- `experiments/26cve/CVE-2023-5798/artifacts/5798-http-observations.txt` (2 trạng thái; chỉ ra rằng plugin asset không lộ version)
- `experiments/pilot-3cve/artifacts/http-verification.txt` (Ca A plugin `ver=`, Ca B REST/JSON:API route, Ca C `/CHANGELOG` 403)
- `experiments/reproduce-cve-2021-41773/{03,04,05}-*.txt` (capture `curl -v` thô: Server header + status, 3 trạng thái)
- `experiments/methods/captures-v2/` (V2 2026-10-16: REST root, 2FA route, plugin readme, registration form — D-034)
- `experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/{427,428}/` (mỗi build: `GET-joomla.xml`, `GET-langmetadata.xml`,
  `GET-api-config-application_public-true` + 3 trang offset, `GET-api-config-application_NO-public-param`, `GET-frontend-root`)
- `experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/{plugin-readme-137.raw.txt,version-observability-138.raw.txt}`
  (version qua `Stable tag`; file 138 là capture nhiều request, phần readme nằm trong đó)
- `experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/{d-137-active-benign-include.raw.txt,d-137-inactive-benign-include.raw.txt,c-138-active-benign-include-control.raw.txt}`
  (reachability: POST benign `Content-Dir`, KHÔNG filter chain)

Các file repro *khác* (`*-repro*.txt`, `*-db-state.txt`, `*-attacker-log*.txt`, sanitizer/browser JSON, `dpkg -l`, image digest,
tarball/zip sha256, và **các capture filter-chain** `a-137-*`, `a2-137-*`, `b-137-*`, `c-138-active-POST-filterchain.raw.txt`,
`run-{a,b,c}-POST-filterchain.raw.txt`) là **ground truth / log khai thác**, KHÔNG dùng để chấm `verified`.
`experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/d-137-nonexistent-path-absent-file.raw.txt` là **control âm của
môi trường** (path không tồn tại → 200 + trang chủ WordPress, KHÔNG phải 404) — dùng để đọc đúng `ambiguity_when`, không phải probe.

---

## CVE-2014-3704 — Drupal 7 "Drupalgeddon" pre-auth SQLi (unauth)

```yaml
CVE-2014-3704:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2014-3704/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "cpe:2.3:a:drupal:drupal:* … versionStartIncluding=7.0, versionEndExcluding=7.32 (vulnerable=true); node khác: cpe:2.3:o:debian:debian_linux:7.0"
      nvd:
        artifact: "data/public-snapshot/CVE-2014-3704/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[] (và configurations.cpeMatch{} trong cùng nvd.json)"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' (Red Hat) → NVD KHÔNG có câu affected-version riêng; dải duy nhất trong nvd.json là tree configurations (giống hệt bản trích của cpe.json ⇒ dư thừa E1, D-017)"
      advisory:
        artifact: "data/public-snapshot/CVE-2014-3704/advisory.html"
        field: "SA-CORE-2014-005 body → khối 'Versions affected' / 'Fixed by'"
        literal: "\"Drupal core 7.x versions prior to 7.32.\" ; \"If you use Drupal 7.x, upgrade to Drupal core 7.32 .\""
    conditions:
      p_product_drupal7:
        {description: "target là Drupal 7", source_ref: "advisory", observable: true, kind: build}
      p_core_version_lt_732:
        {description: "core 7.x < 7.32", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "HTTP chỉ lộ family qua X-Generator: Drupal 7 (không có minor/patch); version đọc từ tarball = ground truth"}
      p_login_form_reachable:
        {description: "form /user/login dựng được (form_build_id/form_token)", source_ref: "nvd/advisory", observable: true, kind: precondition}
      p_array_keys_unsanitised:
        {description: "sink: expandArguments() chưa lọc array-key placeholder (thuộc B — xác định bởi version∈range)", source_ref: "nvd", observable: false, kind: build,
         note: "chỉ phân biệt được bằng chính PoC (SQL error) / patch diff ⇒ needs_control; KHÔNG nằm trong path"}
    paths:
      - {id: path_login_sqli, all_of: [p_login_form_reachable],
         scope_ref: "SA-CORE-2014-005 (7.x < 7.32)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_xgenerator_drupal
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_product_drupal7
        interpret:
          true_when: "header X-Generator khớp '/^Drupal 7\\b/'"
          false_when: "X-Generator hiện diện và KHÔNG khớp 'Drupal 7' (vd 'Drupal 8', 'Drupal 10')"
          ambiguity_when: "X-Generator thiếu/bị strip, hoặc body không phải trang Drupal"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["drupal7_731", "drupal7_732"]
          artifact_refs: ["experiments/26cve/_batch1-stack/artifacts/http-observations.txt"]
          note: "cả hai state đều 'X-Generator: Drupal 7 (http://drupal.org)' → predicate family verified; KHÔNG phân giải được minor"
      - id: probe_login_form
        request: {method: GET, path: "/user/login"}
        maps_to: p_login_form_reachable
        interpret:
          true_when: "HTTP 200 và body chứa 'form_build_id' hoặc 'form_token'"
          false_when: "HTTP 200 trên đúng trang /user/login và body KHÔNG có form đăng nhập (form đã tắt)"
          ambiguity_when: "404/403 (route bị chặn/khác); redirect/200 trang chủ do front-page hoặc cache"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal7_731", "drupal7_732"]
          artifact_refs: []
          note: "không có artifact HTTP capture của /user/login trong case; README chỉ mô tả"
      # p_core_version_lt_732 và p_array_keys_unsanitised: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 1; không có ghi nhận 'dùng để chọn/tinh chỉnh tín hiệu' (spec §5). X-Generator Drupal 7 nằm trong _batch1-stack http-observations nhưng đó là quan sát của batch, không phải ghi nhận development."
```

---

## CVE-2015-3440 — WordPress core < 4.2.1 stored XSS (long comment) (unauth)

```yaml
CVE-2015-3440:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2015-3440/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndIncluding}"
        literal: "cpe:2.3:a:wordpress:wordpress:* … versionEndIncluding=4.2 (vulnerable=true); cộng cpe:2.3:o:debian:debian_linux:7.0 và 8.0"
      nvd:
        artifact: "data/public-snapshot/CVE-2015-3440/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' (Debian) → NVD không có câu affected-version; dải nằm trong configurations (trùng cpe.json)"
      advisory:
        artifact: "data/public-snapshot/CVE-2015-3440/advisory.html"
        field: "wordpress.org/news/2015/04/wordpress-4-2-1 → body"
        literal: "\"WordPress 4.2.1 is now available. This is a critical security release for all previous versions\" ; \"A few hours ago, the WordPress team was made aware of a cross-site scripting vulnerability, which could enable commenters to compromise a site.\""
    conditions:
      p_version_observed:
        {description: "core version string quan sát được qua generator (E5)", source_ref: "E5", observable: true, kind: build,
         note: "khớp với dải <4.2.1 là việc của method theo ranges_by_source (G2)"}
      p_comments_open_on_post:
        {description: "một post có comment_status=open (form bình luận hiển thị)", source_ref: "nvd", observable: true, kind: precondition}
      p_content_column_is_text_64k:
        {description: "comment_content là MySQL TEXT (cắt 64 KB)", source_ref: "nvd", observable: false, kind: precondition,
         note: "schema/DB = ground truth; không có tín hiệu HTTP trước PoC"}
    paths:
      - {id: path_comment_stored_xss, all_of: [p_comments_open_on_post, p_content_column_is_text_64k],
         scope_ref: "wordpress.org 4.2.1 security release (unauthenticated commenter)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa <meta name=\"generator\" content=\"WordPress <ver>\"> — ghi nhận <ver> (vd '4.2-src', '4.2', '4.2.1')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip; token không phải release sạch ('4.2-src' — đã quan sát)"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp420_src", "wp421"]
          artifact_refs: ["experiments/26cve/_batch3-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 8731 → content=\"WordPress 4.2-src\"; 8732 → content=\"WordPress 4.2.1\" (hai trạng thái)"
      - id: probe_comment_form
        request: {method: GET, path: "/?p=1"}
        maps_to: p_comments_open_on_post
        interpret:
          true_when: "HTTP 200 và body chứa form bình luận ('commentform' hoặc textarea[name=comment])"
          false_when: "HTTP 200, bài tồn tại, KHÔNG có form bình luận (comments closed)"
          ambiguity_when: "bài không tồn tại/redirect; hoặc comment form render qua JS"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wp420_src", "wp421"]
          artifact_refs: []
          note: "không có capture HTTP của request này. 3440-browser-xss.json (thực thi JS) và 3440-*-rendered.html (HTML của PoC) là artifact reproduction → KHÔNG dùng để chấm verified"
    decision_inputs: [E1_cpe, E1_nvd, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 3; không có ghi nhận development (spec §5)."
```

---

## CVE-2017-1001000 — WordPress 4.7.x REST API content injection (unauth)

```yaml
CVE-2017-1001000:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2017-1001000/cpe.json"
        field: "cpe_match[] → {cpeName}"  # CPE exact-version (không dạng range; spec §4.2)
        literal: "cpe:2.3:a:wordpress:wordpress:4.7 ; cpe:2.3:a:wordpress:wordpress:4.7.1 ; cpe:2.3:a:wordpress:wordpress:4.7.2 — cả ba vulnerable=true (exact-version, không có versionStart/End)"
      nvd:
        artifact: "data/public-snapshot/CVE-2017-1001000/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → không có câu affected-version; các entry CPE exact nằm trong configurations (trùng cpe.json)"
      advisory:
        artifact: "data/public-snapshot/CVE-2017-1001000/advisory.html"
        field: "make.wordpress.org/core/2017/02/01/disclosure-of-additional-security-fix-in-wordpress-4-7-2 → body"
        literal: "\"WordPress 4.7 and 4.7.1 had one additional vulnerability for which disclosure was delayed. There was an Unauthenticated Privilege Escalation Vulnerability in a REST API … Endpoint.\" ; comment: \".. if you see a “Invalid parameter(s): id” message it’s patched to 4.7.2+\" (advisory KHÔNG có khối 'Affected versions' máy đọc được)"
    conditions:
      p_version_observed:
        {description: "core version string quan sát được qua generator (E5)", source_ref: "E5", observable: true, kind: build}
      p_rest_reachable:
        {description: "REST API gọi được (plain permalinks → ?rest_route=)", source_ref: "nvd", observable: true, kind: precondition}
      p_id_arg_not_integer_checked:
        {description: "sink: tham số id không bị ép integer (bản vá 4.7.2) — thuộc B", source_ref: "advisory", observable: false, kind: build,
         note: "chỉ lộ qua chính request (200 vs 400) ⇒ needs_control; KHÔNG nằm trong path"}
    paths:
      - {id: path_rest_content_injection, all_of: [p_rest_reachable],
         scope_ref: "make.wordpress.org/core 2017-02-01 (unauthenticated REST)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_version_observed
        interpret:
          true_when: "generator content = \"WordPress <ver>\" — ghi nhận <ver> (vd '4.7', '4.7.1', '4.7.2')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp471", "wp472"]
          artifact_refs: ["experiments/26cve/_batch3-stack/artifacts/http-observations.txt"]
      - id: probe_rest_root
        request: {method: GET, path: "/?rest_route=/"}
        maps_to: p_rest_reachable
        interpret:
          true_when: "HTTP 200 và body JSON có 'routes'"
          false_when: "HTTP 200 nhưng body không phải JSON API root (REST trả trang khác)"
          ambiguity_when: "HTTP 404 (REST không expose HOẶC route khác); 401/403 do plugin bảo vệ; redirect do permalink config"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp471", "wp472"]
          artifact_refs: ["experiments/methods/captures-v2/CVE-2017-1001000/8711-wp471-GET-rest-route-index-SUPPLEMENTARY.txt",
                          "experiments/methods/captures-v2/CVE-2017-1001000/8712-wp472-GET-rest-route-index-SUPPLEMENTARY.txt"]
          note: "V2 capture: GET /?rest_route=/ → 200 + JSON 'routes' trên cả 8711 (4.7.1) và 8712 (4.7.2) (D-033 sửa request; D-034 verified)"
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "Batch 3; không có ghi nhận development.; V2 signal-development 2026-10-16 (captures-v2, post-V1 observation)"
```

---

## CVE-2018-7600 — Drupal "Drupalgeddon2" RCE (unauth)

```yaml
CVE-2018-7600:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2018-7600/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndIncluding, versionStartIncluding, versionEndExcluding}"
        literal: "drupal:* versionEndIncluding=7.57 ; drupal:* 8.0.0≤v<8.3.9 ; 8.4.0≤v<8.4.6 ; 8.5.0≤v<8.5.1 (+ cpe:o:debian 7/8/9)"
      nvd:
        artifact: "data/public-snapshot/CVE-2018-7600/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1' (nguồn mlhess@drupal.org) → NVD CÓ câu affected riêng, viết khác dạng CPE (7.57 vs <7.58)"
      advisory:
        artifact: "data/public-snapshot/CVE-2018-7600/advisory.html"
        field: "SA-CORE-2018-002 body → 'Affected versions:'"
        literal: "\">=7.0 <7.58 || >= 8.0.0 <8.3.9 || >=8.4.0 <8.4.6 || >=8.5.0 <8.5.1\""
    conditions:
      p_product_drupal8:
        {description: "target là Drupal 8", source_ref: "advisory", observable: true, kind: build}
      p_core_version_in_affected_86:
        {description: "core 8.5.x < 8.5.1 (nhánh đã dựng)", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "X-Generator chỉ lộ 'Drupal 8'; minor/patch = ground truth (tarball)"}
      p_user_register_ajax_wrapper:
        {description: "route /user/register + AJAX wrapper (_wrapper_format=drupal_ajax) reachable, registration open",
         source_ref: "advisory/nvd", observable: true, kind: precondition}
      p_form_api_render_callback_unsanitised:
        {description: "sink: Form API nhận #post_render/#markup từ input (bản vá 8.5.1) — thuộc B", source_ref: "nvd", observable: false, kind: build,
         note: "chỉ phân biệt bằng chính PoC (output lệnh phản chiếu) ⇒ needs_control; KHÔNG nằm trong path"}
    paths:
      - {id: path_ajax_form_rce, all_of: [p_user_register_ajax_wrapper],
         scope_ref: "SA-CORE-2018-002"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_xgenerator_drupal
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_product_drupal8
        interpret:
          true_when: "X-Generator khớp '/^Drupal 8\\b/'"
          false_when: "X-Generator hiện diện và KHÔNG khớp 'Drupal 8'"
          ambiguity_when: "header thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["drupal8_850", "drupal8_851"]
          artifact_refs: ["experiments/26cve/_batch1-stack/artifacts/http-observations.txt"]
      - id: probe_register_ajax
        request: {method: GET, path: "/user/register"}
        maps_to: p_user_register_ajax_wrapper
        interpret:
          true_when: "HTTP 200 và body chứa 'form_build_id' (form render qua AJAX wrapper)"
          false_when: "HTTP 200 trên đúng /user/register và body KHÔNG có form đăng ký (registration đã tắt)"
          ambiguity_when: "HTTP 403/404 (route bị chặn/khác); 200 nhưng form render khác profile; bị chặn bởi module"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal8_850", "drupal8_851"]
          artifact_refs: ["experiments/26cve/CVE-2018-7600/artifacts/7600-repro.txt (log PoC, KHÔNG phải capture HTTP của probe này)"]
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 1; không có ghi nhận development."
```

---

## CVE-2018-7602 — Drupal "Drupalgeddon3" authenticated RCE (auth) — nhãn trên cặp Drupal 7 7.58/7.59 (D-023)

```yaml
CVE-2018-7602:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2018-7602/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "drupal:* 7.0≤v<7.59 ; 8.4.0≤v<8.4.8 ; 8.5.0≤v<8.5.3 (+ cpe:o:debian 7/8/9)"
      nvd:
        artifact: "data/public-snapshot/CVE-2018-7602/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "[{version:'unspecified', lessThan:'7.59', versionType:'custom'}, {…, lessThan:'8.5.3'}, {…, lessThan:'8.4.8'}] (Drupal core, defaultStatus=unaffected)"
      advisory:
        artifact: "data/public-snapshot/CVE-2018-7602/advisory.html"
        field: "SA-CORE-2018-004 body → 'Affected versions:'"
        literal: "\">=7.0 <7.59 || >= 8.0.0 <8.4.8 || >=8.5.0 <8.5.3\""
    conditions:
      p_product_drupal7:
        {description: "target là Drupal 7 (nhánh đã dựng theo D-023)", source_ref: "advisory", observable: true, kind: build}
      p_core_version_lt_759:
        {description: "core 7.x < 7.59", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "X-Generator chỉ 'Drupal 7'; version = ground truth (tarball 7.58/7.59)"}
      p_authenticated_session:
        {description: "phiên đăng nhập hợp lệ (mở được /user/<uid>/cancel)", source_ref: "advisory", observable: true, kind: precondition}
      p_confirm_form_destination_unsanitised:
        {description: "sink: confirm-form destination render-array chưa sanitise (bản vá 7.59 RequestSanitizer::checkDestination) — thuộc B",
         source_ref: "nvd", observable: false, kind: build, note: "chỉ phân biệt bằng chính chain khai thác ⇒ needs_control; KHÔNG nằm trong path"}
    paths:
      - {id: path_confirm_form_rce, all_of: [p_authenticated_session],
         scope_ref: "SA-CORE-2018-004 (D7 branch 7.x<7.59)"}
  method:
    contract:
      access_model: "auth(any authenticated user opening its own /user/<uid>/cancel confirm form; lab dùng uid 1)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_xgenerator_drupal
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_product_drupal7
        interpret:
          true_when: "X-Generator khớp '/^Drupal 7\\b/'"
          false_when: "X-Generator hiện diện và KHÔNG khớp 'Drupal 7'"
          ambiguity_when: "header thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal7_758", "drupal7_759"]
          artifact_refs: ["experiments/26cve/_batch1-stack/artifacts/http-observations.txt"]
          note: "artifact duy nhất có X-Generator là của cặp 7.31/7.32 (deployment anh em, KHÔNG phải 7.58/7.59 của case này) ⇒ theo luật hai tầng để pending"
      - id: probe_login_form
        request: {method: GET, path: "/user/login"}
        maps_to: p_authenticated_session
        interpret:
          true_when: "HTTP 200 và body chứa 'form_build_id' (form đăng nhập tồn tại)"
          false_when: "HTTP 200 trên đúng /user/login và body KHÔNG có form đăng nhập"
          ambiguity_when: "404/403 (route bị chặn/khác); 200 nhưng không phải form đăng nhập; session cấp sẵn ngoài collector phải ghi rõ (R4)"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal7_758", "drupal7_759"]
          artifact_refs: []
          note: "không có artifact HTTP; case artifact chỉ có d7_7602.py + mysql-shim.php"
      # p_core_version_lt_759, p_confirm_form_destination_unsanitised: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 1 (D-023); không có ghi nhận development."
```

---

## CVE-2019-10692 — WP Google Maps ≤ 7.11.17 unauth SQLi (unauth)

```yaml
CVE-2019-10692:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2019-10692/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding}"
        literal: "cpe:2.3:a:codecabin:wp_go_maps:*:*:*:*:*:wordpress:*:* versionEndExcluding=7.11.18 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2019-10692/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng"
      advisory:
        artifact: "data/public-snapshot/CVE-2019-10692/advisory.html"
        field: "wordpress.org/plugins/wp-google-maps/#developers → changelog body"
        literal: "KHÔNG tìm thấy '7.11.17'/'7.11.18' trong artifact (changelog lưu được chỉ liệt kê các release 10.x gần đây) ⇒ advisory-only KHÔNG có dải máy đọc được cho CVE này → Unknown (spec §4.3)"
    conditions:
      p_plugin_slug_present:
        {description: "plugin WP Google Maps (codecabin) hiện diện (identity → B)", source_ref: "cpe", observable: true, kind: build}
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build,
         note: "readme.txt stable tag là tín hiệu HTTP dự kiến (README P1) nhưng không có artifact"}
      p_markers_route_registered:
        {description: "REST route /wpgmza/v1/markers được đăng ký", source_ref: "nvd", observable: true, kind: precondition}
      p_fields_not_sanitised:
        {description: "sink: tham số fields nối thẳng vào SELECT (bản vá 7.11.18) — thuộc B", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_markers_sqli, all_of: [p_markers_route_registered],
         scope_ref: "NVD CVE-2019-10692 (unauthenticated REST)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/wp-google-maps/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn/xoá); hoặc asset cache-buster không phải version"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wgm_71117", "wgm_71118"]
          artifact_refs: []
          note: "chỉ có artifacts/10692-repro.txt (log khai thác) — không dùng để chấm verified"
      - id: probe_markers_route
        request: {method: GET, path: "/index.php?rest_route=/wpgmza/v1/markers"}
        maps_to: p_markers_route_registered
        interpret:
          true_when: "HTTP 200 và body JSON (route tồn tại)"
          false_when: "HTTP 200 nhưng body không phải JSON của route này"
          ambiguity_when: "HTTP 404 rest_no_route (route không đăng ký HOẶC path khác); 401/403 do plugin/permission; 200 HTML do front controller"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wgm_71117", "wgm_71118"]
          artifact_refs: []
    decision_inputs: [E1_cpe, E1_nvd, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 2; không có ghi nhận development."
```

---

## CVE-2019-6340 — Drupal 8.6.x REST/JSON:API deserialization RCE (pilot Ca B, `auth` per D-015)

```yaml
CVE-2019-6340:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2019-6340/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "cpe:2.3:a:drupal:drupal:* 8.5.0≤v<8.5.11 ; 8.6.0≤v<8.6.10 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2019-6340/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "[{version:'8.5', lessThan:'8.5.11', versionType:'custom'}, {version:'8.6', lessThan:'8.6.10'}] (Drupal Core)"
      advisory:
        artifact: "data/public-snapshot/CVE-2019-6340/advisory.html"
        field: "SA-CORE-2019-003 body → 'Affected versions:' + điều kiện"
        literal: "\">= 8.0.0 <8.5.11 || >=8.6.0 <8.6.10\" ; \"A site is only affected by this if one of the following conditions is met: The site has the Drupal 8 core RESTful Web Services (rest) module enabled and allows GET , PATCH or POST requests, or …\""
    conditions:
      p_product_drupal8:
        {description: "target là Drupal 8", source_ref: "advisory", observable: true, kind: build}
      p_core_version_lt_8610:
        {description: "core 8.6.x < 8.6.10 (nhánh đã dựng)", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "pilot artifact KHÔNG ghi X-Generator; /core/CHANGELOG.txt không mang số version"}
      p_rest_module_on:
        {description: "RESTful Web Services (rest) module bật và nhận POST/PATCH", source_ref: "advisory", observable: true, kind: precondition}
      p_jsonapi_route_on:
        {description: "JSON:API route bật (contrib drupal/jsonapi 8.x-1.24 trên 8.6, D-014)", source_ref: "advisory", observable: true, kind: precondition}
      p_link_field_fixture:
        {description: "entity có field type 'link' (fixture D-015)", source_ref: "nvd", observable: false, kind: precondition,
         note: "field config; quan sát được chỉ khi có quyền/xem field list — ngoài access model unauth"}
      p_auth_content_creation:
        {description: "user có quyền tạo nội dung (basic_auth trong deployment này)", source_ref: "advisory", observable: false, kind: precondition,
         note: "advisory: 'user with the permission to … content creation'; HTTP chỉ lộ form login 200, không lộ role"}
    paths:
      - {id: path_rest, all_of: [p_rest_module_on, p_link_field_fixture, p_auth_content_creation],
         scope_ref: "SA-CORE-2019-003 (REST vector)"}
      - {id: path_jsonapi, all_of: [p_jsonapi_route_on, p_link_field_fixture, p_auth_content_creation],
         scope_ref: "SA-CORE-2019-003 (JSON:API vector) — ĐƯỜNG THAY THẾ, không AND với path_rest"}
  method:
    contract:
      access_model: "auth(content-creation; lab dùng HTTP basic auth admin — xem D-015)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_rest_route
        request: {method: GET, path: "/node/1?_format=hal_json"}
        maps_to: p_rest_module_on
        interpret:
          true_when: "HTTP 200 với body JSON (route REST entity_node tồn tại)"
          false_when: "HTTP 200 nhưng body không phải JSON hal_json của node (route có nhưng format khác)"
          ambiguity_when: "HTTP 403/406/404 (REST không phục vụ / format không bật / route khác); 200 nhưng HTML (front controller nuốt request); redirect"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal869_rest_on", "drupal869_rest_off", "drupal8610_rest_on"]
          artifact_refs: ["experiments/pilot-3cve/artifacts/http-verification.txt"]
          note: "artifact ghi REST -> 200 ở CẢ HAI deployment (8.6.9, 8.6.10) nhưng CHỈ ở trạng thái REST-ON; trạng thái REST-OFF (403) chỉ được ghi trong bảng README §3, không có capture thô ⇒ mới phủ một cực của feature ⇒ pending"
      - id: probe_jsonapi_route
        request: {method: GET, path: "/jsonapi/node/article"}
        maps_to: p_jsonapi_route_on
        interpret:
          true_when: "HTTP 200 với body JSON:API"
          false_when: "HTTP 200 nhưng body không phải JSON:API"
          ambiguity_when: "HTTP 404 (route không tồn tại HOẶC path khác); 403 do permission; hoặc 200 HTML"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal869_jsonapi_contrib", "drupal8610_jsonapi_contrib", "drupal869_jsonapi_on"]
          artifact_refs: ["experiments/pilot-3cve/artifacts/http-verification.txt"]
          note: "artifact ghi JSONAPI -> 404 ở trạng thái module MẶC ĐỊNH (chưa bật) trên cả hai deployment; trạng thái JSON:API-ON → 200 chỉ nằm trong bảng README §3 (không có capture thô) ⇒ mới phủ một cực của feature ⇒ pending"
      - id: probe_login_form
        request: {method: GET, path: "/user/login"}
        maps_to: p_auth_content_creation
        interpret:
          true_when: "HTTP 200 và body chứa form đăng nhập — CHỈ chứng minh có đường đăng nhập, KHÔNG chứng minh role"
          false_when: "HTTP 200 trên đúng /user/login và body KHÔNG có form đăng nhập"
          ambiguity_when: "404/403 (route bị chặn/khác); luôn ambiguous cho role: form login không lộ quyền tạo nội dung"
          otherwise: Unknown
        validation:
          status: needs_control
          control_state_ids: ["drupal869", "drupal8610"]
          artifact_refs: []
          note: "role/permission không có tín hiệu HTTP dưới access model này; nếu session được cấp sẵn NGOÀI collector thì phải ghi rõ account/role + cách chuẩn bị (R4)"
      # p_core_version_lt_8610, p_link_field_fixture: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: true
    used_for_signal_development: true
    reason_ref: "Pilot Ca B (rule development per đề bài; D-014/D-015 + CURRENT_STATE §23–§24: access model = authenticated, fixture field_link, 'success = out-of-band effect not HTTP status')"
```

---

## CVE-2019-6341 — Drupal stored XSS via invalid-UTF-8 upload filename (unauth) — NHÃN GROUND TRUTH = `Unresolved` (D-024)

```yaml
CVE-2019-6341:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2019-6341/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "drupal:* 7.0≤v<7.65 ; 8.5.0≤v<8.5.14 ; 8.6.0≤v<8.6.13 (+ cpe:o:debian:8.0, fedora:28, fedora:29)"
      nvd:
        artifact: "data/public-snapshot/CVE-2019-6341/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "[{version:'Drupal 7', lessThan:'7.65'}, {version:'Drupal 8.6', lessThan:'8.6.13'}, {version:'Drupal 8.5', lessThan:'8.5.14'}]"
      advisory:
        artifact: "data/public-snapshot/CVE-2019-6341/advisory.html"
        field: "SA-CORE-2019-004 body → 'Affected versions:'"
        literal: "\">=7.0 <7.65 || >= 8.0.0 <8.5.14 || >=8.6.0 <8.6.13\""
    conditions:
      p_product_drupal8:
        {description: "target là Drupal 8", source_ref: "advisory", observable: true, kind: build}
      p_core_version_lt_8613:
        {description: "core 8.6.x < 8.6.13", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "X-Generator chỉ 'Drupal 8'; version = tarball ground truth"}
      p_open_registration_user_picture:
        {description: "đăng ký mở + user pictures (managed_file user_picture_0)", source_ref: "advisory", observable: true, kind: precondition}
      p_invalid_utf8_filename_accepted:
        {description: "sink: file_destination()/Unicode::validateUtf8 chấp nhận tên không hợp lệ UTF-8 (bản vá 8.6.13 ném RuntimeException) — thuộc B",
         source_ref: "nvd", observable: false, kind: build, note: "chỉ phân biệt bằng chính upload ⇒ needs_control; KHÔNG nằm trong path"}
      p_browser_executes_stored_file:
        {description: "browser parse file `_0` thành HTML và chạy <script> (impact của stored XSS)", source_ref: "nvd", observable: false, kind: precondition,
         note: "chromium-1208 sniff `text/plain` → KHÔNG quan sát được trong harness ⇒ lý do nhãn Unresolved (D-024)"}
    paths:
      - {id: path_stored_xss_execution, all_of: [p_open_registration_user_picture, p_browser_executes_stored_file],
         scope_ref: "SA-CORE-2019-004 (impact: JS chạy)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_xgenerator_drupal
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_product_drupal8
        interpret:
          true_when: "X-Generator khớp '/^Drupal 8\\b/'"
          false_when: "X-Generator hiện diện và KHÔNG khớp 'Drupal 8'"
          ambiguity_when: "header thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["drupal8_8612", "drupal8_8613"]
          artifact_refs: ["experiments/26cve/_batch1-stack/artifacts/http-observations.txt"]
      - id: probe_register_form
        request: {method: GET, path: "/user/register"}
        maps_to: p_open_registration_user_picture
        interpret:
          true_when: "HTTP 200 + body chứa 'user_picture_0' (managed_file) và 'form_build_id'"
          false_when: "HTTP 200 trên đúng /user/register và body KHÔNG có element user_picture (đăng ký mở nhưng không có ảnh đại diện)"
          ambiguity_when: "HTTP 403 (registration đóng HOẶC bị chặn); profile đăng ký khác; 200 nhưng form render sau JS"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["drupal8_8612", "drupal8_8613"]
          artifact_refs: []
          note: "artifacts/6341-upload.txt là log upload (reproduction), không phải capture của probe này"
      # p_core_version_lt_8613, p_invalid_utf8_filename_accepted, p_browser_executes_stored_file: observable=false
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 1 (D-023 rework). Ground-truth label = Unresolved (D-024: defer to manual reproduction)."
  ground_truth_note: "Nhãn CVE = **Unresolved** (D-024) — KHÔNG đổi nhãn tại đây; chỉ ghi những gì HTTP quan sát được (D-028 R3 + rule 9 của đề bài)."
```

---

## CVE-2019-8942 — WordPress core image-crop RCE (Batch 0, `auth(author)`)

```yaml
CVE-2019-8942:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2019-8942/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding} (kết hợp range + exact-version)"
        literal: "wordpress:* versionEndExcluding=4.9.9 ; wordpress:5.0:- ; 5.0:beta1..beta5 ; 5.0:rc1..rc3 (đều vulnerable=true) (+ cpe:o:debian:9.0)"
      nvd:
        artifact: "data/public-snapshot/CVE-2019-8942/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng (dải nằm ở configurations, trùng cpe.json)"
      advisory:
        artifact: "data/public-snapshot/CVE-2019-8942/advisory.html"
        field: "blog.ripstech.com/2019/wordpress-image-remote-code-execution (đã redirect sang trang blog Sonar) → body"
        literal: "KHÔNG có dải affected trong artifact (trang lưu được là navigation/blog chung, không còn nội dung bài RIPSTECH) ⇒ advisory-only KHÔNG có dải máy đọc được → Unknown (spec §4.3)"
    conditions:
      p_version_observed:
        {description: "core version string quan sát được qua generator (E5)", source_ref: "E5", observable: true, kind: build}
      p_upload_capable_author:
        {description: "role author (upload_files + edit posts)", source_ref: "advisory", observable: false, kind: precondition,
         note: "form login 200 KHÔNG chứng minh role; role = wp-cli ground truth"}
      p_image_editor_and_self_fetch:
        {description: "GD/Imagick + theme dir ghi được + container self-fetch được URL của chính nó", source_ref: "nvd", observable: false, kind: precondition}
      p_meta_input_unfiltered:
        {description: "sink: post-meta meta_input không bị lọc (bản vá 5.0.1) — thuộc B", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_crop_rce, all_of: [p_upload_capable_author, p_image_editor_and_self_fetch],
         scope_ref: "CVE-2019-8942 / RIPSTECH chain (authenticated author)"}
  method:
    contract:
      access_model: "auth(author)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_version_observed
        interpret:
          true_when: "generator content = \"WordPress <ver>\" — ghi nhận <ver> (vd '5.0', '5.0.0', '5.0.1')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip; hoặc cache trả version khác"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp500", "wp501"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 8111 → content=\"WordPress 5.0\"; 8112 → content=\"WordPress 5.0.1\""
      - id: probe_login_page
        request: {method: GET, path: "/wp-login.php"}
        maps_to: p_upload_capable_author
        interpret:
          true_when: "không có giá trị true_when an toàn — trang login KHÔNG lộ role"
          false_when: "HTTP 200 trên đúng /wp-login.php và body KHÔNG phải trang login"
          ambiguity_when: "404/403 (trang login bị chặn/khác); luôn ambiguous cho role: 200 chỉ chứng minh có đường đăng nhập"
          otherwise: Unknown
        validation:
          status: needs_control
          control_state_ids: ["wp500", "wp501"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "README ghi rõ: 'login page present … not itself proof of an author account'"
      # p_image_editor_and_self_fetch, p_meta_input_unfiltered: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E2, E3, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "Batch 0 = de-risk probe (selection-log §Batch 0: 'WP-core RCE with a real precondition (author) flagged for de-risk'; CURRENT_STATE §31) — cờ này để researcher xác nhận; README ghi nhận tường minh 'P2 … not itself proof of an author account' (không có tín hiệu role qua HTTP)."
```

---

## CVE-2020-12625 — Roundcube stored XSS in HTML/CDATA messages (pilot Ca C, `auth`)

```yaml
CVE-2020-12625:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2020-12625/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding}"
        literal: "cpe:2.3:a:roundcube:webmail:* versionEndExcluding=1.4.4 (vulnerable=true) (+ cpe:o:debian 9/10, cpe:a:opensuse:backports_sle 15.0:sp1/sp2, cpe:o:opensuse:leap 15.1/15.2)"
      nvd:
        artifact: "data/public-snapshot/CVE-2020-12625/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng"
      advisory:
        artifact: "data/public-snapshot/CVE-2020-12625/advisory.html"
        field: "roundcube.net/news/2020/04/29/security-updates-1.4.4-1.3.11-and-1.2.10 → khối 'Security fixes'"
        literal: "\"Cross-Site Scripting (XSS) via malicious HTML content ( CVE-2020-12625 ) **\" ; \"See the full changelogs … 1.4.4 , 1.3.11 and 1.2.10 .\" (advisory KHÔNG có khối range dạng bảng; dải suy ra: 1.4.x<1.4.4, 1.3.x<1.3.11, 1.2.x<1.2.10)"
    conditions:
      p_product_roundcube:
        {description: "target là Roundcube Webmail", source_ref: "advisory", observable: true, kind: build}
      p_version_lt_144:
        {description: "Roundcube 1.4.x < 1.4.4 (nhánh đã dựng)", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "/CHANGELOG /INSTALL 403; asset chỉ có cache-buster 10 chữ số → version không quan sát được unauth"}
      p_message_view_auth:
        {description: "phiên đăng nhập đọc được mail HTML", source_ref: "advisory", observable: false, kind: precondition,
         note: "login 302 là bằng chứng đăng nhập (ground truth), không phải quan sát role/target state"}
      p_cdata_unescaped:
        {description: "sink: rcube_washtml không escape CDATA (bản vá 1.4.4) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_browser_executes:
        {description: "browser chạy <script> từ CDATA (impact)", source_ref: "nvd", observable: false, kind: precondition,
         note: "out-of-band (browser harness), không phải HTTP quan sát"}
    paths:
      - {id: path_cdata_xss, all_of: [p_message_view_auth, p_browser_executes],
         scope_ref: "Roundcube 1.4.4 security update (CVE-2020-12625)"}
  method:
    contract:
      access_model: "auth(victim reads message; attacker delivers HTML via SMTP)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_login_page
        request: {method: GET, path: "/?_task=login"}
        maps_to: p_product_roundcube
        interpret:
          true_when: "HTTP 200 và body chứa dấu hiệu Roundcube (vd 'rcmail', 'roundcube', form login webmail)"
          false_when: "HTTP 200 và body là trang webmail khác (product khác)"
          ambiguity_when: "chỉ có status 200/404 (artifact hiện chỉ ghi status) → không đủ để khẳng định product"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc143", "rc144"]
          artifact_refs: ["experiments/pilot-3cve/artifacts/http-verification.txt"]
          note: "artifact chỉ ghi 'GET /?_task=login -> 200' (không lưu body/marker) ⇒ chưa đủ chấm verified"
      # p_version_lt_144, p_message_view_auth, p_cdata_unescaped, p_browser_executes: observable=false
      # quan sát phủ định có thật (dùng làm evidence_ref cho p_version_lt_144):
      #   GET /CHANGELOG → 403 trên CẢ 1.4.3 và 1.4.4 (http-verification.txt) ⇒ 'version không quan sát được'
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: true
    used_for_signal_development: true
    reason_ref: "Pilot Ca C (rule development per đề bài; CURRENT_STATE §23–§24 + §22 item 4: 'Roundcube version is not HTTP-observable' — finding đã vào R1/observability)"
```

---

## CVE-2020-12640 — Roundcube LFI via crafted `plugins` option (config-gated: một block, hai trạng thái, D-023)

```yaml
CVE-2020-12640:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2020-12640/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "roundcube:webmail:* 1.2.0≤v<1.2.10 ; 1.3.0≤v<1.3.11 ; 1.4.0≤v<1.4.4 (+ cpe:a:opensuse:backports_sle:15.0, cpe:o:opensuse:leap 15.1/15.2)"
      nvd:
        artifact: "data/public-snapshot/CVE-2020-12640/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng"
      advisory:
        artifact: "data/public-snapshot/CVE-2020-12640/advisory.html"
        field: "roundcube.net/news/2020/04/29/… → khối 'Security fixes'"
        literal: "\"Path traversal vulnerability allowing local file inclusion via crafted ‘plugins’ option ( CVE-2020-12640 ) **\" ; \"The latter two vulnerabilities are classified minor because they only affect Roundcube installations with public access to the Roundcube installer.\""
    conditions:
      p_product_roundcube:
        {description: "target là Roundcube Webmail", source_ref: "advisory", observable: true, kind: build}
      p_version_lt_144:
        {description: "Roundcube < 1.4.4", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "version không quan sát được unauth (image digest = ground truth)"}
      p_installer_public:
        {description: "thư mục /installer/ CÔNG KHAI và còn bật (điều kiện advisory nêu)", source_ref: "advisory", observable: true, kind: precondition}
      p_attacker_writes_local_php:
        {description: "attacker ghi được file PHP cục bộ (qua installer/khác)", source_ref: "advisory", observable: false, kind: precondition}
      p_plugins_option_traversal:
        {description: "sink: config 'plugins' chứa tên traversal (bản vá 1.4.4 lọc /[^a-zA-Z0-9_-]/) — thuộc B", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_config_on, all_of: [p_installer_public, p_attacker_writes_local_php],
         scope_ref: "case config-on (installer-created config simulated). Trạng thái config-off = p_installer_public=False trên chính đường này ⇒ nhánh-b (KHÔNG tạo đường NOT())"}
  method:
    contract:
      access_model: "unauth (attacker dùng installer công khai để set config; sau đó request bất kỳ trigger include)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_installer_dir
        request: {method: GET, path: "/installer/"}
        maps_to: p_installer_public
        interpret:
          true_when: "HTTP 200 và body là trang Roundcube Installer (form cấu hình/DB)"
          false_when: "HTTP 200 nhưng body KHÔNG phải Roundcube Installer"
          ambiguity_when: "HTTP 404 (không có /installer/ HOẶC path khác); 403; 302/redirect do web server"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc143_default_config_off", "rc143_config_on", "rc144_config_on"]
          artifact_refs: []
          note: "README P2 nêu 'GET /installer/ → 200' là tín hiệu dự kiến; artifacts/12640-lfi.txt là log PoC LFI, KHÔNG dùng để chấm verified"
      - id: probe_login_page
        request: {method: GET, path: "/?_task=login"}
        maps_to: p_product_roundcube
        interpret:
          true_when: "HTTP 200 và body chứa dấu hiệu Roundcube"
          false_when: "HTTP 200 và body là trang webmail khác (product khác)"
          ambiguity_when: "chỉ có status 200/404 → không đủ để khẳng định product"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc143_default_config_off", "rc143_config_on", "rc144_config_on"]
          artifact_refs: []
      # p_version_lt_144, p_attacker_writes_local_php, p_plugins_option_traversal: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 4 config-gated (D-022/D-023); không có ghi nhận development."
  ground_truth_note: "Hai trạng thái đối chứng trong MỘT block: default config-off = Not Applicable (nhánh b); config-on 1.4.3 = Applicable; config-on 1.4.4 = NA (a). Không tạo section thứ hai (đề bài rule 8)."
```

---

## CVE-2020-12641 — Roundcube command injection via `im_convert_path` (config-gated: một block, hai trạng thái, D-023)

```yaml
CVE-2020-12641:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2020-12641/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "roundcube:webmail:* 1.2.0≤v<1.2.10 ; 1.3.0≤v<1.3.11 ; 1.4.0≤v<1.4.4 (+ opensuse entries)"
      nvd:
        artifact: "data/public-snapshot/CVE-2020-12641/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng"
      advisory:
        artifact: "data/public-snapshot/CVE-2020-12641/advisory.html"
        field: "roundcube.net/news/2020/04/29/… → khối 'Security fixes'"
        literal: "\"Remote code execution via crafted config options ( CVE-2020-12641 ) **\" ; \"The latter two vulnerabilities are classified minor because they only affect Roundcube installations with public access to the Roundcube installer.\""
    conditions:
      p_product_roundcube:
        {description: "target là Roundcube Webmail", source_ref: "advisory", observable: true, kind: build}
      p_version_lt_144:
        {description: "Roundcube < 1.4.4", source_ref: "cpe/advisory", observable: false, kind: build}
      p_installer_public:
        {description: "/installer/ công khai (để set config)", source_ref: "advisory", observable: true, kind: precondition}
      p_im_convert_path_set:
        {description: "sink: im_convert_path (metacharacter) đưa vào exec không escapeshellcmd (bản vá 1.4.4) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_image_attachment_resize:
        {description: "thumbnail request (_action=get&_thumb=1) trên ảnh >240px kích hoạt resize()", source_ref: "nvd", observable: true, kind: precondition}
    paths:
      - {id: path_config_on, all_of: [p_installer_public, p_image_attachment_resize],
         scope_ref: "case config-on (im_convert_path attacker-controlled). Trạng thái config-off = p_installer_public=False ⇒ nhánh-b (KHÔNG tạo đường NOT())"}
  method:
    contract:
      access_model: "unauth (public installer set config; trigger cần phiên đọc mail để lấy attachment — lab dùng test/test)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_installer_dir
        request: {method: GET, path: "/installer/"}
        maps_to: p_installer_public
        interpret:
          true_when: "HTTP 200 và body là Roundcube Installer"
          false_when: "HTTP 200 nhưng body KHÔNG phải Roundcube Installer"
          ambiguity_when: "HTTP 404/403 (không có installer HOẶC bị chặn); 302/redirect; 200 trang khác"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc143_default_config_off", "rc143_config_on", "rc144_config_on"]
          artifact_refs: []
          note: "artifacts/12641-rce.txt + rc_trigger_thumb.py là reproduction, KHÔNG dùng để chấm verified"
      - id: probe_login_page
        request: {method: GET, path: "/?_task=login"}
        maps_to: p_product_roundcube
        interpret:
          true_when: "HTTP 200 và body chứa dấu hiệu Roundcube"
          false_when: "HTTP 200 và body là trang webmail khác (product khác)"
          ambiguity_when: "chỉ có status 200/404 → không đủ để khẳng định product"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc143_default_config_off", "rc143_config_on", "rc144_config_on"]
          artifact_refs: []
      # p_version_lt_144, p_im_convert_path_set: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 4 config-gated (D-022/D-023); không có ghi nhận development."
  ground_truth_note: "Một block cho hai trạng thái (rule 8): default config-off = Not Applicable (nhánh b); config-on 1.4.3 = Applicable; config-on 1.4.4 = NA (a)."
```

---

## CVE-2020-13671 — Drupal core filename sanitisation → upload RCE (config-gated: một block, hai trạng thái, D-023)

```yaml
CVE-2020-13671:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2020-13671/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "drupal:* 7.0≤v<7.74 ; 8.8.0≤v<8.8.11 ; 8.9.0≤v<8.9.9 ; 9.0.0≤v<9.0.8 (+ fedora 32/33)"
      nvd:
        artifact: "data/public-snapshot/CVE-2020-13671/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "['9.0 versions prior to 9.0.8', '8.9 versions prior to 8.9.9', '8.8 versions prior to 8.8.11', '7 versions prior to 7.74'] (Drupal Core)"
      advisory:
        artifact: "data/public-snapshot/CVE-2020-13671/advisory.html"
        field: "SA-CORE-2020-012 body → 'Affected versions:'"
        literal: "\">=7.0 <7.74 || >= 8.0.0 <8.8.11 || >= 8.9.0 <8.9.9 || >=9.0.0 <9.0.8\""
    conditions:
      p_product_drupal8:
        {description: "target là Drupal 8", source_ref: "advisory", observable: true, kind: build}
      p_core_version_lt_899:
        {description: "core 8.9.x < 8.9.9 (nhánh đã dựng)", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "X-Generator chỉ 'Drupal 8'; minor/patch = tarball ground truth"}
      p_unsafe_ext_file_field:
        {description: "tồn tại file field cho phép extension không an toàn (vd 'png php')", source_ref: "advisory", observable: false, kind: precondition,
         note: "field config; default standard profile KHÔNG có → đây chính là điều kiện config-gate"}
      p_upload_permission:
        {description: "quyền upload/tạo nội dung", source_ref: "advisory", observable: false, kind: precondition}
      p_name_not_munged:
        {description: "sink: file_munge_filename giữ nguyên tên (bản vá 8.9.9 đổi thành poc.php_.png) — thuộc B", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_config_on, all_of: [p_unsafe_ext_file_field, p_upload_permission],
         scope_ref: "case config-on (file field cho phép 'png php'). Trạng thái config-off = p_unsafe_ext_file_field=False ⇒ nhánh-b (KHÔNG tạo đường NOT())"}
  method:
    contract:
      access_model: "auth(upload/content-creation; fixture field)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_xgenerator_drupal
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_product_drupal8
        interpret:
          true_when: "X-Generator khớp '/^Drupal 8\\b/'"
          false_when: "X-Generator hiện diện và KHÔNG khớp 'Drupal 8'"
          ambiguity_when: "header thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["drupal8_898", "drupal8_899"]
          artifact_refs: ["experiments/26cve/_batch1-stack/artifacts/http-observations.txt"]
      # p_core_version_lt_899, p_unsafe_ext_file_field, p_upload_permission, p_name_not_munged: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 1 config-gated (D-023); không có ghi nhận development."
  ground_truth_note: "Một block cho hai trạng thái (rule 8): default config-off = Not Applicable (nhánh b); config-on 8.9.8 = Applicable; config-on 8.9.9 = NA (a). Artifact 13671-munge.txt là diff của sink (drush php:eval), KHÔNG phải HTTP."
```

---

## CVE-2020-25213 — WordPress File Manager unauth upload RCE (unauth)

```yaml
CVE-2020-25213:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2020-25213/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding}"
        literal: "cpe:2.3:a:filemanagerpro:file_manager:*:*:*:*:free:wordpress:*:* versionEndExcluding=6.9 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2020-25213/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng"
      advisory:
        artifact: "data/public-snapshot/CVE-2020-25213/advisory-fallback.html (primary = advisory-primary.error.txt, HTTP 403 JS bot-challenge)"
        field: "wordpress.org/plugins/wp-file-manager/ → changelog body"
        literal: "\"6.9 (1st Sept, 2020) Security issue fixed\" (changelog vendor). KHÔNG có khối range dạng máy đọc được cho CVE-2020-25213 ⇒ advisory fallback không cho dải; ghi Unknown cho advisory-only range (spec §4.3/§4.4)"
    conditions:
      p_plugin_wfm_present:
        {description: "plugin File Manager (wp-file-manager) hiện diện (identity → B)", source_ref: "cpe", observable: true, kind: build}
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build}
      p_connector_reachable:
        {description: "lib/php/connector.minimal.php gọi được không cần xác thực", source_ref: "nvd", observable: true, kind: precondition}
      p_upload_writable_no_block:
        {description: "thư mục upload ghi được và không chặn thực thi", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_elfinder_upload_rce, all_of: [p_connector_reachable, p_upload_writable_no_block],
         scope_ref: "NVD CVE-2020-25213 (CISA KEV)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/wp-file-manager/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn/xoá); hoặc nested-zip install để version khác zip ngoài (đã ghi trong README)"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wfm_60", "wfm_806"]
          artifact_refs: []
          note: "artifacts/25213-repro.txt là log khai thác; fixed control dùng 8.0.6 (D-021) nên '>=6.9' vẫn đúng semantics"
      - id: probe_connector
        request: {method: GET, path: "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"}
        maps_to: p_connector_reachable
        interpret:
          true_when: "HTTP 200 (connector tồn tại và trả lời)"
          false_when: "HTTP 200 nhưng body không phải response của connector"
          ambiguity_when: "HTTP 301/302/404 (connector đã bị gỡ HOẶC path khác); 403 do WAF; 200 nhưng body rỗng"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wfm_60", "wfm_806"]
          artifact_refs: []
          note: "README ghi fixed 8.0.6 → connector 301; nhưng không có file capture HTTP riêng"
    decision_inputs: [E1_cpe, E1_nvd, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 2; không có ghi nhận development. (Advisory primary bị chặn bot → fallback vendor; ghi nhận dữ liệu, không phải development.)"
```

---

## CVE-2021-23017 — nginx resolver off-by-one (backport, một trạng thái) — `Not Applicable (a)`

```yaml
CVE-2021-23017:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2021-23017/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding} (25 entry, KHÔNG product-scoped — spec §4.1)"
        literal: "cpe:2.3:a:f5:nginx:* versionStartIncluding=0.6.18, versionEndExcluding=1.20.1 (vulnerable=true); cộng 24 entry khác product (openresty, fedora, netapp, oracle …)"
      nvd:
        artifact: "data/public-snapshot/CVE-2021-23017/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='Nginx Web Server, Nginx Plus', version='Nginx Web Server versions 0.6.18 thru 1.20.0 before 1.20.1, Nginx plus versions R13 thru R23 before R23 P1. Nginx plus version R24 before R24 P1'"
      advisory:
        artifact: "data/public-snapshot/CVE-2021-23017/advisory.html"
        field: "ubuntu.com/security/CVE-2021-23017 → bảng 'Fixed' theo release (không có 'Affected versions' dạng CPE)"
        literal: "\"Fixed 1.18.0-6ubuntu9\" (22.04 jammy); \"Fixed 1.18.0-6ubuntu8.2\" (21.10); \"Fixed 1.18.0-6ubuntu2.2\" (20.10); \"Fixed 1.18.0-0ubuntu1.2\" (20.04); \"7.7 · High\""
    conditions:
      p_nginx_product:
        {description: "target là nginx (upstream)", source_ref: "cpe/nvd", observable: true, kind: build}
      p_version_observed:
        {description: "version string quan sát được qua Server header (E5)", source_ref: "E5", observable: true, kind: build,
         note: "header chỉ lộ 'nginx/<ver>' (family/minor), KHÔNG lộ package revision — 'nginx/1.18.0 (Ubuntu)' giống hệt trên bản patched và unpatched (R2/D-020.2)"}
      p_build_patched_backport:
        {description: "build đang chạy ĐÃ có bản vá backport của Ubuntu", source_ref: "advisory (distro) + E4", observable: false, kind: build,
         note: "KHÔNG có header nào lộ package revision; 'nginx/1.18.0 (Ubuntu)' giống hệt trên bản patched và unpatched (R2/D-020.2)"}
    paths:
      - {id: path_resolver_offbyone, all_of: [],
         scope_ref: "Ubuntu USN-4967-1/2 + nginx upstream 1.20.1 — KHÔNG có precondition quan sát được; bỏ NOT(p_build_patched_backport) (G4): B (build vá/không vá) do luật method xử (E1/E4/E5)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_server_header
        request: {method: HEAD, path: "/"}
        maps_to: p_version_observed
        interpret:
          true_when: "header Server khớp '/^nginx\\/<ver>/' — ghi nhận <ver> (vd '1.18.0')"
          false_when: "Server hiện diện nhưng không parse được version"
          ambiguity_when: "server_tokens off (Server chỉ 'nginx'), header thiếu, hoặc reverse proxy ghi đè"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["nginx_jammy_backport_1.18.0-6ubuntu14.21"]
          artifact_refs: ["experiments/26cve/CVE-2021-23017/artifacts/23017-nginx-observable-vs-truth.txt",
                           "experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "CHỈ MỘT trạng thái triển khai (case Not Applicable-a); artifact là capture HTTP thật của HEAD / (200 + 'Server: nginx/1.18.0 (Ubuntu)'). E5 (chuỗi version) QUAN SÁT ĐƯỢC nhưng E4 (phân biệt build vá/chưa vá) KHÔNG nối được target↔build và KHÔNG có trạng thái affected đối chứng ⇒ hạ verified→pending (review 2026-10-14 §2 G6 + §3 B1/P1); output phương pháp = Unknown, không phải 'fusion thắng'."
      # p_build_patched_backport: observable=false → KHÔNG có probe (đây chính là kết luận của case: E4 không nối được target↔build
      #   bằng HTTP ⇒ output phương pháp phải là Unknown, không phải 'fusion thắng'; dpkg -l = ground truth, không phải scanner input)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E4, E5, E6→Unknown]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "D-020.2 + README §'The observable / ground-truth separation' + CURRENT_STATE §31: finding 'header không phân biệt được package revision → method output Unknown' ĐÃ được dùng để sửa R2 (E4 cần target↔build linkage)."
```

---

## CVE-2021-24917 — WPS Hide Login ≤ 1.9 protection bypass / secret-login disclosure (unauth)

```yaml
CVE-2021-24917:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2021-24917/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding}"
        literal: "cpe:2.3:a:wpserveur:wps_hide_login:*:*:*:*:*:wordpress:*:* versionEndExcluding=1.9.1 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2021-24917/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "vendor='Unknown', product='WPS Hide Login', versions=[{version:'1.9.1', lessThan:'1.9.1', versionType:'custom', status:'affected'}] (nguồn contact@wpscan.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2021-24917/advisory.html"
        field: "wpscan.com/vulnerability/15bb711a-… → tiêu đề + khối 'Fixed in'"
        literal: "\"WPS Hide Login < 1.9.1 – Protection Bypass with Referer-Header\" (CVE 2021-24917) ; \"Fixed in 1.9.1\""
    conditions:
      p_plugin_whl_present:
        {description: "plugin WPS Hide Login hiện diện (identity → B)", source_ref: "cpe", observable: true, kind: build}
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build}
      p_secret_login_configured:
        {description: "đã cấu hình URL đăng nhập bí mật (whl_page)", source_ref: "nvd", observable: true, kind: precondition}
      p_referer_bypass_leaks_secret:
        {description: "sink: referer bypass làm lộ secret trong Location (bản vá 1.9.1 → '?404') — thuộc B", source_ref: "nvd", observable: false, kind: build,
         note: "chỉ phân biệt được bằng chính request khai thác (302 Location) ⇒ needs_control; KHÔNG nằm trong path"}
    paths:
      - {id: path_referer_disclosure, all_of: [p_secret_login_configured],
         scope_ref: "WPScan 15bb711a (CVE-2021-24917)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/wps-hide-login/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn/xoá)"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["whl_19", "whl_191"]
          artifact_refs: []
      - id: probe_secret_login_redirect
        request: {method: GET, path: "/wp-login.php", headers: ["no Referer"]}
        maps_to: p_secret_login_configured
        interpret:
          true_when: "302 và Location KHÔNG trỏ tới chính /wp-login.php (login mặc định bị ẩn)"
          false_when: "không có false_when dương an toàn cho cấu hình này (200 form mặc định là nhập nhằng — xem ambiguity_when)"
          ambiguity_when: "HTTP 200 với form đăng nhập mặc định của WordPress (có thể 'chưa cấu hình' HOẶC plugin không hoạt động); 404/403; redirect tới trang khác không chứa slug bí mật"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["whl_19", "whl_191"]
          artifact_refs: []
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Replacement (Batch 2/3 continuation); không có ghi nhận development."
```

---

## CVE-2021-29447 — WordPress core XXE in Media Library (PHP 8 only) (Batch 0, `auth(author)`)

```yaml
CVE-2021-29447:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2021-29447/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "cpe:2.3:a:wordpress:wordpress:* versionStartIncluding=5.6.0, versionEndExcluding=5.7.1 (vulnerable=true) (+ cpe:o:debian 9.0/10.0)"
      nvd:
        artifact: "data/public-snapshot/CVE-2021-29447/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='wordpress-develop', version='>= 5.6.0, < 5.7.1' (GitHub security-advisories)"
      advisory:
        artifact: "data/public-snapshot/CVE-2021-29447/advisory.html"
        field: "GHSA-rv47-pc52-qrhh → khối 'Affected versions' / 'Patched versions'"
        literal: "\"Affected versions 5.6 - 5.7\" ; \"Patched versions 5.7.1\" ; \"This has been patched in WordPress version 5.7.1 …\""
    conditions:
      p_version_observed:
        {description: "core version string quan sát được qua generator (E5)", source_ref: "E5", observable: true, kind: build}
      p_php8_runtime:
        {description: "runtime PHP 8", source_ref: "advisory/nvd", observable: true, kind: precondition}
      p_author_upload:
        {description: "role author (upload_files)", source_ref: "advisory", observable: false, kind: precondition,
         note: "form login 200 không chứng minh role"}
      p_getid3_external_entities:
        {description: "sink: getID3 iXML parse với external entities (bản vá 5.7.1) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_oob_attacker_reachable:
        {description: "server fetch được host attacker (DTD out-of-band)", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_media_xxe, all_of: [p_php8_runtime, p_author_upload, p_oob_attacker_reachable],
         scope_ref: "GHSA-rv47-pc52-qrhh (authenticated author, upload)"}
  method:
    contract:
      access_model: "auth(author; upload_files)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_version_observed
        interpret:
          true_when: "generator content = \"WordPress <ver>\" — ghi nhận <ver> (vd '5.6.0', '5.7', '5.7.1')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp570_php803", "wp571_php806"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 8121 → content=\"WordPress 5.7\"; 8122 → content=\"WordPress 5.7.1\""
      - id: observe_php_version
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_php8_runtime
        interpret:
          true_when: "header X-Powered-By khớp '/^PHP\\/8\\./'"
          false_when: "X-Powered-By hiện diện và KHÔNG khớp 'PHP/8.' (đã loại trừ proxy strip)"
          ambiguity_when: "header thiếu/bị strip bởi proxy/WAF; hoặc giá trị bị ghi đè"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp570_php803", "wp571_php806"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 'X-Powered-By: PHP/8.0.3' (8121) vs 'X-Powered-By: PHP/8.0.6' (8122) — cả hai đều PHP 8 ⇒ predicate PHP-8 verified trên cả hai trạng thái (đúng R3: bản fixed không biến feature thành False)"
      - id: probe_login_page
        request: {method: GET, path: "/wp-login.php"}
        maps_to: p_author_upload
        interpret:
          true_when: "không có giá trị true_when an toàn — trang login KHÔNG lộ role"
          false_when: "HTTP 200 trên đúng /wp-login.php và body KHÔNG phải trang login"
          ambiguity_when: "404/403 (trang login bị chặn/khác); luôn ambiguous cho role: 200 chỉ chứng minh có đường đăng nhập"
          otherwise: Unknown
        validation:
          status: needs_control
          control_state_ids: ["wp570_php803", "wp571_php806"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
      # p_getid3_external_entities, p_oob_attacker_reachable: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "Batch 0 (de-risk) + CURRENT_STATE §31: 'PHP 8 precondition IS HTTP-observable (X-Powered-By: PHP/8.0.3 vs 8.0.6)' — finding này đã vào cách chọn tín hiệu (E6 runtime precondition)."
```

---

## CVE-2021-41773 — Apache httpd 2.4.49 path traversal / file disclosure (pilot, unauth)

```yaml
CVE-2021-41773:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2021-41773/cpe.json"
        field: "cpe_match[] → {cpeName}"  # exact-version, không range (spec §4.2)
        literal: "cpe:2.3:a:apache:http_server:2.4.49 (vulnerable=true, KHÔNG có versionStart/End) (+ fedora 34/35, oracle, netapp)"
      nvd:
        artifact: "data/public-snapshot/CVE-2021-41773/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='Apache HTTP Server', version='Apache HTTP Server 2.4 2.4.49' (nguồn security@apache.org)"
      advisory:
        artifact: "data/public-snapshot/CVE-2021-41773/advisory.html"
        field: "httpd.apache.org/security/vulnerabilities_24.html → mục 'Fixed in Apache HTTP Server 2.4.51' / 'critical: Path traversal and file disclosure …'"
        literal: "\"critical: Path traversal and file disclosure vulnerability in Apache HTTP Server 2.4.49 ( CVE-2021-41773 )\" ; \"This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.\" ; \"Affects 2.4.50, 2.4.49\" ; \"Update 2.4.51 released 2021-10-07\""
    conditions:
      p_version_observed:
        {description: "httpd version quan sát được qua Server header (E5)", source_ref: "E5", observable: true, kind: build}
      p_diroots_require_all_granted:
        {description: "tiền điều kiện config: <Directory /> đặt 'Require all granted' (misconfig; advisory: 'if files outside docroot are not protected by require all denied, these requests can succeed')", source_ref: "advisory", observable: false, kind: precondition,
         note: "biểu hiện HTTP duy nhất của điều kiện này LÀ chính request traversal (403 vs 200); không có probe benign → observable:false"}
      p_file_outside_docroot:
        {description: "tồn tại file ngoài DocumentRoot (lab: marker) mà attacker biết đường dẫn", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_traversal_disclosure, all_of: [p_diroots_require_all_granted, p_file_outside_docroot],
         scope_ref: "CVE-2021-41773 (pilot reproduction 2026-10-04)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_server_header
        request: {method: HEAD, path: "/"}
        maps_to: p_version_observed
        interpret:
          true_when: "header Server khớp '/^Apache\\/2\\.4\\.[0-9]+/' — ghi nhận <ver>"
          false_when: "Server hiện diện nhưng không parse được version"
          ambiguity_when: "ServerTokens Prod (ẩn version) / header bị ghi đè"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["httpd2449_default_8081", "httpd2449_weakened_8083", "httpd2451_8082"]
          artifact_refs: ["experiments/reproduce-cve-2021-41773/03-lab-traversal.txt",
                           "experiments/reproduce-cve-2021-41773/04-fixed-251-traversal.txt",
                           "experiments/reproduce-cve-2021-41773/05-default-249-traversal.txt"]
          note: "capture curl -v thô có response header thật: 'Server: Apache/2.4.49 (Unix)' (8081/8083) vs 'Server: Apache/2.4.51 (Unix)' (8082) ⇒ Server-header predicate verified trên cả ba trạng thái. (File nằm ở gốc case dir, không phải artifacts/ — ghi nhận để researcher chuẩn hoá đường dẫn.)"
      # p_diroots_require_all_granted, p_file_outside_docroot: observable=false → KHÔNG có probe.
      # Lý do (quan trọng): cách duy nhất để phân biệt config <Directory /> qua HTTP trong case này LÀ chính request traversal
      # (8083→200 marker, 8081→403). Đó là request khai thác (impact path), không phải probe feature benign ⇒ theo luật hai tầng
      # (D-028 R3) điều kiện config này để observable:false, KHÔNG biến capture reproduction thành 'verified'.
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6→Unknown]
  development_use:
    used_for_rule_development: true
    used_for_signal_development: true
    reason_ref: "Pilot #1 (CURRENT_STATE §3/§11/§12) — case dạy 'affected version ≠ applicable trong deployment config'; là điểm khởi đầu của thiết kế (D-007/D-008)."
```

---

## CVE-2021-42013 — Apache httpd 2.4.50 path traversal variant (unauth)

```yaml
CVE-2021-42013:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2021-42013/cpe.json"
        field: "cpe_match[] → {cpeName}"  # exact-version cho 2.4.49/2.4.50
        literal: "cpe:2.3:a:apache:http_server:2.4.49 và :2.4.50 (đều vulnerable=true) (+ fedora 34/35, oracle, netapp)"
      nvd:
        artifact: "data/public-snapshot/CVE-2021-42013/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='Apache HTTP Server', versions=['Apache HTTP Server 2.4.49', 'Apache HTTP Server 2.4.50']"
      advisory:
        artifact: "data/public-snapshot/CVE-2021-42013/advisory.html"
        field: "httpd.apache.org/security/vulnerabilities_24.html → mục 'Fixed in Apache HTTP Server 2.4.51'"
        literal: "\"critical: Path Traversal and Remote Code Execution in Apache HTTP Server 2.4.49 and 2.4.50 (incomplete fix of CVE-2021-41773)  ( CVE-2021-42013 )\" ; \"It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient.\""
    conditions:
      p_version_observed:
        {description: "httpd version quan sát được qua Server header (E5)", source_ref: "E5", observable: true, kind: build}
      p_diroots_require_all_granted:
        {description: "tiền điều kiện config: <Directory /> 'Require all granted' (misconfig)", source_ref: "advisory", observable: false, kind: precondition,
         note: "config precondition trên đường tác động DUY NHẤT: config-off = giá trị False ⇒ nhánh-b (G4); biểu hiện HTTP duy nhất LÀ chính request traversal (403 vs 200) nên observable:false, không có probe benign"}
      p_double_decode_reaches_file:
        {description: "sink: double-encode %%32%65 vượt bản vá 2.4.50 (bản vá 2.4.51 → 400) — thuộc B", source_ref: "advisory", observable: false, kind: build}
    paths:
      - {id: path_traversal_variant, all_of: [p_diroots_require_all_granted],
         scope_ref: "CVE-2021-42013 (incomplete fix of 41773)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_server_header
        request: {method: HEAD, path: "/"}
        maps_to: p_version_observed
        interpret:
          true_when: "header Server khớp '/^Apache\\/2\\.4\\.<ver>/' — ghi nhận <ver> (vd '2.4.50')"
          false_when: "Server hiện diện nhưng không parse được version"
          ambiguity_when: "ServerTokens Prod (ẩn version); header bị ghi đè"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["httpd2450_8860", "httpd2451_8861"]
          artifact_refs: ["experiments/26cve/CVE-2021-42013/artifacts/42013-repro.txt"]
          note: "artifact có dòng 'Server: Server: Apache/2.4.50 (Unix)' (8860) và 'Apache/2.4.51 (Unix)' (8861) ⇒ hai trạng thái, capture thật"
      # p_diroots_require_all_granted, p_double_decode_reaches_file: observable=false → không có probe (cùng lý do như 41773)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6→Unknown]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 1a; không có ghi nhận development (case lặp lại mô-típ 41773 nhưng không phải nguồn sửa rule)."
```

---

## CVE-2021-44026 — Roundcube authenticated SQLi in search (auth)

```yaml
CVE-2021-44026:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2021-44026/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "roundcube:webmail:* versionEndExcluding=1.3.17 ; roundcube:webmail:* 1.4.0≤v<1.4.12 (+ fedora 33/34, debian 9/10/11)"
      nvd:
        artifact: "data/public-snapshot/CVE-2021-44026/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "affected: vendor='n/a', product='n/a', version='n/a' → NVD không có câu affected-version riêng"
      advisory:
        artifact: "data/public-snapshot/CVE-2021-44026/advisory.html"
        field: "github.com/roundcube/roundcubemail/commit/c8947ecb → body"
        literal: "KHÔNG có dải version trong artifact (trang commit GitHub: tiêu đề 'Rename session items ‘search’ and ‘search_params’ to ‘contact_search…’', không có khối affected-range) ⇒ advisory-only range = Unknown (spec §4.3)"
    conditions:
      p_product_roundcube:
        {description: "target là Roundcube Webmail", source_ref: "cpe", observable: true, kind: build}
      p_version_lt_1412:
        {description: "Roundcube 1.4.x < 1.4.12", source_ref: "cpe", observable: false, kind: build,
         note: "version không quan sát được unauth"}
      p_auth_session:
        {description: "phiên đăng nhập Roundcube", source_ref: "nvd", observable: false, kind: precondition}
      p_sort_reaches_session:
        {description: "sink: _sort chưa bị lọc regex (bản vá ca5dd519) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_contacts_fixture:
        {description: "≥1 dòng trong <db>.contacts của user (nếu 0 dòng, AND SLEEP() không được đánh giá)", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_export_sqli, all_of: [p_auth_session, p_contacts_fixture],
         scope_ref: "Roundcube 1.4.12 security update (CVE-2021-44026)"}
  method:
    contract:
      access_model: "auth(test/test — chain cần phiên RC hợp lệ)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_login_page
        request: {method: GET, path: "/?_task=login"}
        maps_to: p_product_roundcube
        interpret:
          true_when: "HTTP 200 và body chứa dấu hiệu Roundcube"
          false_when: "HTTP 200 và body là trang webmail khác (product khác)"
          ambiguity_when: "chỉ có status 200/404 → không đủ để khẳng định product"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc1411", "rc1412"]
          artifact_refs: []
          note: "artifacts/44026-sqli.txt + rc_44026.py là log khai thác (timing), KHÔNG dùng để chấm verified"
      # p_version_lt_1412, p_auth_session, p_sort_reaches_session, p_contacts_fixture: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 4; không có ghi nhận development."
```

---

## CVE-2022-21661 — WordPress core WP_Query SQLi (Batch 0, unauth, fixture plugin)

```yaml
CVE-2022-21661:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2022-21661/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding} (27 entry, nhiều nhánh; spec §4.1)"
        literal: "wordpress:* 3.7≤v<3.7.37 … 5.7≤v<5.7.5 ; 5.8≤v<5.8.3 (nhánh dựng được) (+ fedora 34/35, debian 9/10/11)"
      nvd:
        artifact: "data/public-snapshot/CVE-2022-21661/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='wordpress-develop', version='< 5.8.3' (GitHub security-advisories)"
      advisory:
        artifact: "data/public-snapshot/CVE-2022-21661/advisory.html"
        field: "wordpress.org/news/2022/01/wordpress-5-8-3-security-release/ → body"
        literal: "\"Four security issues affect WordPress versions between 3.7 and 5.8 …\" ; \"Props to ngocnb and khuyenn from GiaoHangTietKiem JSC for working with Trend Micro Zero Day Initiative on reporting a SQL injection vulnerability in WP_Query.\" — advisory KHÔNG có khối 'Affected versions' theo từng CVE; dải suy ra từ câu chung (3.7–5.8, fixed 5.8.3)"
    conditions:
      p_version_observed:
        {description: "core version string quan sát được qua generator (E5)", source_ref: "E5", observable: true, kind: build}
      p_trigger_plugin_present:
        {description: "plugin/theme chuyển input người dùng vào WP_Query (fixture Ele Custom Skin 3.1.3, D-020.1)", source_ref: "nvd", observable: true, kind: precondition}
      p_fixture_route_unauth:
        {description: "fixture expose query không cần xác thực (wp_ajax_nopriv_ecsload)", source_ref: "nvd", observable: true, kind: precondition}
      p_query_not_int_cast:
        {description: "sink: 5.8.3 ép int cho các field (bản vá) — thuộc B", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_wpquery_sqli, all_of: [p_trigger_plugin_present, p_fixture_route_unauth],
         scope_ref: "wordpress.org 5.8.3 release + ZDI-22-020 (fixture = phần của case identity, D-020.1)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_version_observed
        interpret:
          true_when: "generator content = \"WordPress <ver>\" — ghi nhận <ver> (vd '5.8.2', '5.8.3')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp582", "wp583"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 8131 → content=\"WordPress 5.8.2\"; 8132 → content=\"WordPress 5.8.3\""
      - id: observe_fixture_asset_version
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_trigger_plugin_present
        interpret:
          true_when: "body chứa 'wp-content/plugins/ele-custom-skin/assets/' với '?ver=3.1.3'"
          false_when: "asset ele-custom-skin hiện diện với version KHÁC 3.1.3; hoặc plugin vắng"
          ambiguity_when: "asset bị minify/không cache-buster; hoặc plugin active nhưng không enqueue asset ở trang chủ"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp582", "wp583"]
          artifact_refs: ["experiments/26cve/_batch0-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 'ECS fixture asset: ele-custom-skin/assets/css/ecs-style.css?ver=3.1.3' trên CẢ HAI state (fixture là hằng số, chỉ core đổi)"
      - id: probe_fixture_route
        request: {method: POST, path: "/wp-admin/admin-ajax.php", headers: ["Content-Type: application/x-www-form-urlencoded"],
                  body: "action=ecsload&ecs_ajax_settings={…}&query={…}"}
        maps_to: p_fixture_route_unauth
        interpret:
          true_when: "route tồn tại (không trả 400 'action not found'); phản hồi có thể 500 do fixture gọi Elementor"
          false_when: "không có false_when dương an toàn — 500 giống nhau ở cả hai trạng thái KHÔNG phân biệt được route thiếu hay handler lỗi"
          ambiguity_when: "HTTP 400 với body '0' hoặc 'action not found' (route không đăng ký HOẶC admin-ajax bị chặn); 403 do WAF"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wp582", "wp583"]
          artifact_refs: ["experiments/26cve/CVE-2022-21661/artifacts/21661-repro-vuln.txt (timing + status, KHÔNG phải capture HTTP phân biệt route)"]
          note: "README nêu HTTP 500 GIỐNG NHAU ở cả hai trạng thái; tín hiệu thật là timing + DB general log (ground truth) ⇒ không thể verified bằng HTTP"
      # p_query_not_int_cast: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "Batch 0 (de-risk) — selection-log: 'WP-core SQLi requiring a plugin/theme fixture flagged for de-risk'; D-020.1 chốt 'fixture = part of case identity'; README ghi nhận tường minh tín hiệu HTTP không phân biệt (500 cả hai) và fixture asset là tín hiệu quan sát được. Researcher xác nhận cờ này (xem Open items)."
```

---

## CVE-2023-2745 — WordPress core ≤ 6.2 traversal via `wp_lang` (unauth)

```yaml
CVE-2023-2745:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2023-2745/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding} (22 entry)"
        literal: "wordpress:* <4.1.38 ; 4.2≤v<4.2.35 ; … ; 6.0≤v<6.0.4 ; 6.1≤v<6.1.2 ; wordpress:6.2 (exact, vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2023-2745/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "vendor='WordPress Foundation', product='WordPress', versions=[{version:'0', lessThan:'4.1.38', versionType:'semver'}, … {version:'6.2', …}] (nguồn security@wordfence.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2023-2745/advisory.html"
        field: "wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/ → body"
        literal: "\"WordPress 6.2.1 is now available!\" ; \"This release also features several security fixes. Because this is a security release … All versions since WordPress 4.1 have also been updated.\" — KHÔNG có khối affected-range theo CVE ⇒ advisory-only dải suy ra: fixed 6.2.1, các nhánh cũ backport"
    conditions:
      p_version_observed:
        {description: "core version string quan sát được qua generator (E5)", source_ref: "E5", observable: true, kind: build}
      p_wp_lang_unsanitised:
        {description: "sink: determine_locale() nhận wp_lang chưa lọc (bản vá sanitize_locale_name) — thuộc B", source_ref: "nvd", observable: false, kind: build,
         note: "chỉ lộ qua chính request khai thác (reflection trong <html lang>) ⇒ needs_control; KHÔNG nằm trong path"}
      p_crafted_mo_present:
        {description: "tồn tại file .mo hợp lệ tại đường dẫn traversal (cần upload/plant trước)", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_wp_lang_traversal, all_of: [p_crafted_mo_present],
         scope_ref: "wordpress.org 6.2.1 release (CVE-2023-2745)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_version_observed
        interpret:
          true_when: "generator content = \"WordPress <ver>\" — ghi nhận <ver> (vd '6.2', '6.2.1')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["wp620", "wp621"]
          artifact_refs: ["experiments/26cve/_batch3-stack/artifacts/http-observations.txt"]
          note: "quan sát thật: 8721 → content=\"WordPress 6.2\"; 8722 → content=\"WordPress 6.2.1\""
      # p_wp_lang_unsanitised (sink), p_crafted_mo_present: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 3; không có ghi nhận development."
```

---

## CVE-2023-28121 — WooCommerce Payments auth bypass → admin creation (unauth, replacement)

```yaml
CVE-2023-28121:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2023-28121/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "woocommerce_payments:* 4.8.0≤v<4.8.2 ; 5.0.0≤v<5.0.4 ; 5.1.0≤v<5.1.3 ; 5.2.0≤v<5.2.2 ; 5.5.0≤v<5.5.2 ; woopayments:* 5.6.0≤v<5.6.2 ; woopayments 4.9.0/5.3.0/5.4.0 (exact)"
      nvd:
        artifact: "data/public-snapshot/CVE-2023-28121/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='WooCommerce Payments WordPress Plugin', version='Fixed version 5.6.2' (nguồn support@hackerone.com) — NVD ghi 'fixed version', KHÔNG liệt kê dải"
      advisory:
        artifact: "data/public-snapshot/CVE-2023-28121/advisory.html"
        field: "developer.woocommerce.com/2023/03/23/… → 'Patched WooCommerce Payments (WooPayments) Versions'"
        literal: "\"All websites with WooCommerce Payments 4.8.0 and higher installed and activated on their site … are still potentially vulnerable\" ; \"Patched … 4.8.2 / 4.9.1 / 5.0.4 / 5.1.3 / 5.2.2 / 5.3.1 / 5.4.1 / 5.5.2 / 5.6.2 …\""
    conditions:
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build}
      p_woocommerce_active:
        {description: "WooCommerce active (dependency)", source_ref: "nvd", observable: true, kind: precondition}
      p_platform_checkout_header_trusted:
        {description: "sink: header X-WCPAY-PLATFORM-CHECKOUT-USER được tin (fix: bỏ hook Platform_Checkout_Session::init()) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_known_admin_id:
        {description: "biết user id admin (1)", source_ref: "nvd", observable: true, kind: precondition}
    paths:
      - {id: path_platform_checkout_bypass, all_of: [p_woocommerce_active, p_known_admin_id],
         scope_ref: "WooCommerce advisory 2023-03-23 (CVE-2023-28121)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/woocommerce-payments/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn); hoặc plugin đổi slug sang 'woopayments'"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wcpay_561", "wcpay_562"]
          artifact_refs: []
          note: "artifacts/28121-repro.txt là log khai thác; không dùng để chấm verified"
      - id: probe_users_route
        request: {method: GET, path: "/wp-json/wp/v2/users"}
        maps_to: p_known_admin_id
        interpret:
          true_when: "HTTP 200 và body JSON liệt kê user (id=1 admin)"
          false_when: "HTTP 200 nhưng body KHÔNG phải JSON liệt kê user của route này"
          ambiguity_when: "401/403 (REST users bị chặn/WAF); 200 rỗng do cấu hình ẩn author"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["wcpay_561", "wcpay_562"]
          artifact_refs: []
      # p_woocommerce_active: quan sát được (asset wc-*) nhưng không có artifact → xem Open items
      # p_platform_checkout_header_trusted: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Replacement R-B (selection-log 2026-10-10 continuation); không có ghi nhận development."
```

---

## CVE-2023-32243 — Essential Addons for Elementor unauth account takeover (unauth)

```yaml
CVE-2023-32243:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2023-32243/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "cpe:2.3:a:wpdeveloper:essential_addons_for_elementor:*:*:*:*:*:wordpress:*:* versionStartIncluding=5.4.0, versionEndExcluding=5.7.1 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2023-32243/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "packageName='essential-addons-for-elementor-lite', versions=[{version:'5.4.0', lessThanOrEqual:'5.7.1', changes:[{at:'5.7.2', status:'unaffected'}]}] (nguồn audit@patchstack.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2023-32243/advisory.html"
        field: "patchstack.com/articles/… → body"
        literal: "\"The plugin Essential Addons for Elementor (versions >= 5.4.0 and <= 5.7.1 , free version) …\" ; \"The described vulnerability was fixed in version 5.7.2 and assigned CVE-2023-32243 .\" ; \"please update the plugin to at least version 5.7.2\""
    conditions:
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build}
      p_elementor_active:
        {description: "Elementor active (dependency)", source_ref: "nvd", observable: true, kind: precondition}
      p_eael_nonce_unauth:
        {description: "nonce lấy được không cần xác thực (action=eael_get_token)", source_ref: "nvd", observable: true, kind: precondition}
      p_reset_key_unvalidated:
        {description: "sink: reset_password() không kiểm password-reset-key (bản vá 5.7.2) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_known_username:
        {description: "biết username admin (id 1)", source_ref: "nvd", observable: true, kind: precondition}
    paths:
      - {id: path_password_reset_takeover, all_of: [p_elementor_active, p_eael_nonce_unauth, p_known_username],
         scope_ref: "Patchstack CVE-2023-32243"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/essential-addons-for-elementor-lite/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn/xoá)"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["ea_571", "ea_572"]
          artifact_refs: []
          note: "artifacts/32243-repro.txt là log khai thác (account takeover), KHÔNG dùng để chấm verified"
      - id: probe_eael_token
        request: {method: POST, path: "/wp-admin/admin-ajax.php", headers: ["Content-Type: application/x-www-form-urlencoded"],
                  body: "action=eael_get_token"}
        maps_to: p_eael_nonce_unauth
        interpret:
          true_when: "HTTP 200 và body JSON có trường 'nonce'"
          false_when: "HTTP 200 nhưng body KHÔNG chứa trường 'nonce'"
          ambiguity_when: "HTTP 400 hoặc body '0' (action không đăng ký HOẶC handler nopriv thiếu); 403 do WAF; nonce trả qua HTML"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["ea_571", "ea_572"]
          artifact_refs: []
      - id: probe_users_route
        request: {method: GET, path: "/wp-json/wp/v2/users"}
        maps_to: p_known_username
        interpret:
          true_when: "HTTP 200 JSON có 'slug' user (enumeration username)"
          false_when: "HTTP 200 nhưng body KHÔNG phải JSON liệt kê user của route này"
          ambiguity_when: "401/403 (REST users bị chặn/WAF); 200 rỗng do cấu hình ẩn author"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["ea_571", "ea_572"]
          artifact_refs: []
      # p_elementor_active: quan sát qua asset trên / (không có artifact) — xem Open items
      # p_reset_key_unvalidated: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 2; không có ghi nhận development."
```

---

## CVE-2023-3460 — Ultimate Member registration privilege escalation (unauth)

```yaml
CVE-2023-3460:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2023-3460/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding}"
        literal: "cpe:2.3:a:ultimatemember:ultimate_member:*:*:*:*:*:wordpress:*:* versionEndExcluding=2.6.7 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2023-3460/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='Ultimate Member', versions=[{version:'0', lessThan:'2.6.7', versionType:'custom', status:'affected'}] (nguồn contact@wpscan.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2023-3460/advisory.html"
        field: "wpscan.com/vulnerability/694235c7-… → tiêu đề + khối 'Fixed in' + PoC"
        literal: "\"Ultimate Member < 2.6.7 – Unauthenticated Privilege Escalation | CVE 2023-3460\" ; \"Fixed in 2.6.7\" ; PoC: \"POST /register/ HTTP/1.1\""
    conditions:
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build}
      p_open_registration_form:
        {description: "form đăng ký UM (default form id 7) reachable + _wpnonce", source_ref: "nvd", observable: true, kind: precondition}
      p_metakey_filter_bypassable:
        {description: "sink: is_metakey_banned bypass (wp_càpabilities + ký tự có dấu) — bản vá 2.6.7 — thuộc B", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_registration_privesc, all_of: [p_open_registration_form],
         scope_ref: "WPScan 694235c7 (CVE-2023-3460)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/ultimate-member/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn/xoá)"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["um_266", "um_267"]
          artifact_refs: ["experiments/methods/captures-v2/CVE-2023-3460/8830-um266-GET-readme.txt",
                          "experiments/methods/captures-v2/CVE-2023-3460/8831-um267-GET-readme.txt"]
          note: "V2 capture: Stable tag 2.6.6 (8830) vs 2.6.7 (8831) (D-034 verified)"
          note: "artifacts/3460-repro.txt là log khai thác; không dùng để chấm verified"
      - id: probe_um_register_form
        request: {method: GET, path: "/?page_id=6"}
        maps_to: p_open_registration_form
        interpret:
          true_when: "HTTP 200 và body chứa 'um-form' + 'user_login-7' + '_wpnonce'"
          false_when: "HTTP 200 trên đúng trang form và body KHÔNG có 'um-form'/'user_login-7' (form đăng ký không render)"
          ambiguity_when: "404 (trang form không tồn tại HOẶC form ở trang khác); form id/trang khác; plain permalinks vs pretty"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["um_266", "um_267"]
          artifact_refs: ["experiments/methods/captures-v2/CVE-2023-3460/8830-um266-GET-register-page.txt",
                          "experiments/methods/captures-v2/CVE-2023-3460/8831-um267-GET-page_id6-AS-SPECIFIED.txt"]
          note: "V2 capture: GET /?page_id=6 → 200 + um-form + user_login-7 + _wpnonce trên cả hai state (fixture đã align, D-034 verified)"
      # p_metakey_filter_bypassable: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "Batch 2; không có ghi nhận development.; V2 signal-development 2026-10-16 (captures-v2, post-V1 observation)"
```

---

## CVE-2023-5631 — Roundcube stored XSS via SVG in HTML messages (auth) — NHÃN GROUND TRUTH = `Unresolved` (D-024)

```yaml
CVE-2023-5631:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2023-5631/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding, versionStartIncluding}"
        literal: "roundcube:webmail:* versionEndExcluding=1.4.15 ; 1.5.0≤v<1.5.5 ; 1.6.0≤v<1.6.4 (+ debian 10/11/12, fedora 39)"
      nvd:
        artifact: "data/public-snapshot/CVE-2023-5631/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "[{version:'1.6.0', lessThan:'1.6.3', versionType:'semver'}, {version:'1.5.0', lessThan:'1.5.4'}, {version:'1.4.0', lessThan:'1.5.14'}, {version:'1.6.4', status:'unaffected'}, {version:'1.5.5', status:'unaffected'}] (nguồn security@eset.com) — LƯU Ý: NVD ở đây KHÁC CPE (1.6.3 vs 1.6.4) ⇒ mâu thuẫn phạm vi cần ghi nhận"
      advisory:
        artifact: "data/public-snapshot/CVE-2023-5631/advisory.html"
        field: "roundcube.net/news/2023/10/16/security-update-1.6.4-released → body"
        literal: "\"We just published a security update to the version 1.6 of Roundcube Webmail. It provides a fix to a recently reported XSS vulnerability: Fix cross-site scripting (XSS) vulnerability in handling of SVG in HTML messages (#9168)\" ; \"We strongly recommend to update all productive installations of Roundcube 1.6.x with this new version.\" (không có khối affected-range)"
    conditions:
      p_product_roundcube:
        {description: "target là Roundcube Webmail", source_ref: "advisory", observable: true, kind: build}
      p_version_lt_1415_or_155:
        {description: "Roundcube < 1.4.15 / 1.5.x < 1.5.5 (case: 1.4.11 / fixed control 1.5.5)", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "version không quan sát được unauth"}
      p_crafted_html_mail:
        {description: "sink: thư HTML chứa data-URI SVG có whitespace ('image/s vg+xml') qua được sanitizer — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_message_view_auth:
        {description: "phiên đọc mail", source_ref: "nvd", observable: false, kind: precondition}
      p_browser_renders_use_data_uri:
        {description: "browser render <use href=\"data:…\"> và chạy JS bên trong (impact)", source_ref: "nvd", observable: false, kind: precondition,
         note: "chromium-1208 CHẶN (SVG <use> local-scheme rule) ⇒ không quan sát được ⇒ lý do nhãn Unresolved"}
    paths:
      - {id: path_in_browser_execution, all_of: [p_message_view_auth, p_browser_renders_use_data_uri],
         scope_ref: "G5 — impact = browser thực thi (đường tác động DUY NHẤT); bỏ đường 'injection sống qua sanitizer' (sink thuộc B)"}
  method:
    contract:
      access_model: "auth(victim reads message; attacker đưa mail qua SMTP)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_login_page
        request: {method: GET, path: "/?_task=login"}
        maps_to: p_product_roundcube
        interpret:
          true_when: "HTTP 200 và body chứa dấu hiệu Roundcube"
          false_when: "HTTP 200 và body là trang webmail khác (product khác)"
          ambiguity_when: "chỉ có status 200/404 → không đủ để khẳng định product"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc1411", "rc155"]
          artifact_refs: []
      # p_version_lt_1415_or_155, p_message_view_auth, p_browser_renders_use_data_uri: observable=false → không có probe
      # (observe_message_html đã BỎ theo G5/B2: nó quan sát chính sink crafted mail, không phải tiền điều kiện benign)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 4 (D-023 rework). Ground-truth label = Unresolved (D-024)."
  ground_truth_note: "Nhãn CVE = **Unresolved** (D-024) — không đổi nhãn tại đây; ghi nhận: NVD affected (1.6.3/1.5.4) KHÁC CPE (1.6.4/1.5.5) → mâu thuẫn phạm vi cần researcher xử ở tầng rule (spec §4.2/§4.3)."
```

---

## CVE-2023-5798 — WP plugin "Assistant" Editor+ SSRF (replacement, `auth(Editor+)`)

```yaml
CVE-2023-5798:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2023-5798/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding}"
        literal: "cpe:2.3:a:fastlinemedia:assistant:*:*:*:*:*:wordpress:*:* versionEndExcluding=1.4.4 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2023-5798/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "product='Assistant', versions=[{version:'0', lessThan:'1.4.4', versionType:'semver', status:'affected'}] (nguồn contact@wpscan.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2023-5798/advisory.html"
        field: "wpscan.com/vulnerability/bbb4c98c-… → tiêu đề + 'Fixed in' + PoC"
        literal: "\"Assistant < 1.4.4 – Editor+ SSRF | CVE 2023-5798\" ; \"As an Editor or above, open http://example.com/index.php?fl_asst_image_proxy&url=https://127.0.0.1\" ; \"Fixed in 1.4.4\""
    conditions:
      p_version_observed:
        {description: "plugin version quan sát được unauth (E5)", source_ref: "E5", observable: false, kind: build,
         note: "plugin version KHÔNG quan sát được unauth — README/artifact xác nhận không có asset '?ver=' trên front/login"}
      p_editor_role:
        {description: "role Editor+ (gate current_user_can('edit_others_posts'))", source_ref: "advisory", observable: false, kind: precondition}
      p_proxy_unvalidated:
        {description: "sink: ImageProxy dùng wp_remote_get (bản vá 1.4.4 → wp_safe_remote_get + esc_url_raw) — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_image_content_type_echo:
        {description: "proxy chỉ echo body khi Content-Type bắt đầu bằng image/ (phụ, không cần cho SSRF)", source_ref: "nvd", observable: false, kind: build}
    paths:
      - {id: path_image_proxy_ssrf, all_of: [p_editor_role],
         scope_ref: "WPScan bbb4c98c (CVE-2023-5798)"}
  method:
    contract:
      access_model: "auth(Editor+)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_home_no_assistant_version
        request: {method: GET, path: "/wp-login.php"}
        maps_to: p_version_observed
        interpret:
          true_when: "KHÔNG có giá trị true_when — probe âm (observability): xác nhận KHÔNG có asset 'assistant' với '?ver=' ⇒ version không quan sát được"
          false_when: "tìm thấy asset 'assistant/...?ver=<version>' (khi đó version ĐÃ quan sát được)"
          ambiguity_when: "plugin active nhưng không enqueue asset ở trang này; hoặc asset bị minify → 'không thấy' ≠ 'version ngoài dải'"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["asst_143", "asst_144"]
          artifact_refs: ["experiments/26cve/CVE-2023-5798/artifacts/5798-http-observations.txt"]
          note: "capture thật cho CẢ HAI trạng thái: 'assistant asset: (rỗng)' trên 8611 (1.4.3) và 8612 (1.4.4) ⇒ predicate 'plugin version KHÔNG quan sát được unauth' được verified. Đây là probe âm (observability), không phải probe khẳng định version."
      - id: probe_login_page
        request: {method: GET, path: "/wp-login.php"}
        maps_to: p_editor_role
        interpret:
          true_when: "không có true_when an toàn — form login KHÔNG lộ role"
          false_when: "HTTP 200 trên đúng /wp-login.php và body KHÔNG phải trang login"
          ambiguity_when: "404/403 (trang login bị chặn/khác); luôn ambiguous cho role: 200 chỉ chứng minh có đường đăng nhập"
          otherwise: Unknown
        validation:
          status: needs_control
          control_state_ids: ["asst_143", "asst_144"]
          artifact_refs: ["experiments/26cve/CVE-2023-5798/artifacts/5798-http-observations.txt"]
      # p_proxy_unvalidated, p_image_content_type_echo: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: true
    reason_ref: "README §'Precondition table' + §'Scenario tags': 'ẩn-version — the plugin version is not observable unauthenticated' + artifact 5798-http-observations.txt. Finding này là ví dụ mà đề bài nêu cho nhóm ẩn-version."
```

---

## CVE-2024-10924 — Really Simple Security auth bypass (2FA-gated) (pilot Ca A, unauth)

```yaml
CVE-2024-10924:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2024-10924/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "really_simple_security:* (flavor '-'/'pro'/'pro_multisite') 9.0.0≤v<9.1.2 (vulnerable=true, 3 entry)"
      nvd:
        artifact: "data/public-snapshot/CVE-2024-10924/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "vendor='Really Simple Plugins' / 'rogierlankhorst', versions=[{version:'9.0.0', lessThanOrEqual:'9.1.1.1', versionType:'semver', status:'affected'}] (nguồn security@wordfence.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2024-10924/advisory-fallback.html (primary = advisory-primary.error.txt, HTTP 202 Cloudflare challenge)"
        field: "wordpress.org/plugins/really-simple-ssl/ → changelog body"
        literal: "\"9.1.2   Security: authentication bypass fix\" (+ mục '9.1.1.1 – 2024-11-05'). Fallback vendor KHÔNG có khối affected-range dạng máy đọc được ⇒ advisory-only dải = Unknown (spec §4.3); fixed version đọc được = 9.1.2"
    conditions:
      p_version_observed:
        {description: "plugin version quan sát được qua asset '?ver=' trên /wp-login.php (E5)", source_ref: "E5", observable: true, kind: build}
      p_core_version_671:
        {description: "WordPress core 6.7.1 (nền chung của case — KHÔNG phải tiền điều kiện của lỗ hổng)", source_ref: "nvd", observable: true, kind: build}
      p_2fa_enabled:
        {description: "2FA (login protection) BẬT — cổng của lỗ hổng", source_ref: "advisory", observable: "indirect", kind: precondition,
         note: "route two_fa chỉ được đăng ký khi 2FA bật ⇒ POST thiếu tham số → 400 rest_missing_callback_param (bật) vs 404 rest_no_route (tắt)"}
      p_skip_onboarding_route:
        {description: "route /really-simple-security/v1/two_fa/skip_onboarding tồn tại", source_ref: "nvd", observable: true, kind: precondition}
    paths:
      - {id: path_two_fa_skip_onboarding, all_of: [p_2fa_enabled, p_skip_onboarding_route],
         scope_ref: "Wordfence 2024-11 disclosure (CVE-2024-10924) — 2FA là điều kiện bắt buộc"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_asset_version
        request: {method: GET, path: "/wp-login.php"}
        maps_to: p_version_observed
        interpret:
          true_when: "asset của really-simple-ssl có '?ver=' với token version parse được — ghi nhận <ver> (vd '9.1.1.1')"
          false_when: "asset hiện diện nhưng '?ver=' không parse được thành version"
          ambiguity_when: "asset không xuất hiện/không cache-buster version; hoặc plugin đổi tên slug"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["rss_9111_2fa_on", "rss_9111_2fa_off", "rss_912_2fa_on"]
          artifact_refs: ["experiments/pilot-3cve/artifacts/http-verification.txt"]
          note: "capture thật: 'plugin asset ver -> ver=9.1.1.1' (8081, 9.1.1.1) vs 'ver=9.1.2' (8082, fixed)"
      - id: observe_wp_generator
        request: {method: GET, path: "/", headers: ["Accept: text/html"]}
        maps_to: p_core_version_671
        interpret:
          true_when: "generator content = \"WordPress <ver>\" — ghi nhận <ver> (case nền: '6.7.1')"
          false_when: "generator hiện diện nhưng không có token version parse được"
          ambiguity_when: "generator thiếu/bị strip"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["rss_9111_2fa_on", "rss_912_2fa_on"]
          artifact_refs: ["experiments/pilot-3cve/artifacts/http-verification.txt"]
      - id: probe_two_fa_route
        request: {method: POST, path: "/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding",
                  headers: ["Content-Type: application/json"], body: "{}  # KHÔNG gửi nonce/user_id — chỉ dò sự tồn tại route"}
        maps_to: p_2fa_enabled
        interpret:
          true_when: "HTTP 400 với mã 'rest_missing_callback_param' (route tồn tại ⇒ 2FA đang bật)"
          false_when: "HTTP 404 với mã 'rest_no_route' (route chưa đăng ký ⇒ 2FA tắt — mã lỗi cụ thể, verified D-034)"
          ambiguity_when: "404 trần/khác; 401/403 (REST bị chặn toàn cục); 200 (không nên xảy ra khi thiếu tham số); WAF can thiệp"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["rss_9111_2fa_on", "rss_9111_2fa_off", "rss_912_2fa_on"]
          artifact_refs: ["experiments/methods/captures-v2/CVE-2024-10924/8081-2fa-on-POST-skip_onboarding.txt",
                          "experiments/methods/captures-v2/CVE-2024-10924/8081-2fa-off-POST-skip_onboarding.txt"]
          note: "V2 capture: 2FA-on → 400 rest_missing_callback_param; 2FA-off → 404 rest_no_route (D-033 sửa namespace; D-034 verified). Fixed 9.1.2 cũng 400 nhưng B=False (version)."
      # p_skip_onboarding_route: quan sát được qua chính probe_two_fa_route (cùng request) — không tạo probe thứ hai (R4: 2 extraction trên 1 response = 1 request)
    decision_inputs: [E1_cpe, E1_nvd, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: true
    used_for_signal_development: true
    reason_ref: "Pilot Ca A (rule development per đề bài; D-015 + CURRENT_STATE §23 items (2),(4): tín hiệu route 2FA 400-vs-404, và fixed path trả 500 thay vì 403)"
```

---

## CVE-2024-28000 — LiteSpeed Cache unauth privilege escalation (unauth)

```yaml
CVE-2024-28000:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2024-28000/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "cpe:2.3:a:litespeedtech:litespeed_cache:*:*:*:*:*:wordpress:*:* versionStartIncluding=1.9, versionEndExcluding=6.4 (vulnerable=true)"
      nvd:
        artifact: "data/public-snapshot/CVE-2024-28000/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "packageName='litespeed-cache', versions=[{version:'0', lessThanOrEqual:'6.3.0.1', changes:[{at:'6.4', status:'unaffected'}]}] (nguồn audit@patchstack.com)"
      advisory:
        artifact: "data/public-snapshot/CVE-2024-28000/advisory.html"
        field: "patchstack.com/database/… → khối 'Vulnerable version(s)' / 'Patched version'"
        literal: "\"WordPress LiteSpeed Cache Plugin <= 6.3.0.1 is vulnerable to a high priority Privilege Escalation\" ; \"Vulnerable version(s) 6.3.0.1\" ; \"Patched version 6.4\" ; \"Update to version 6.4 or later to resolve the vulnerability.\""
    conditions:
      p_version_observed:
        {description: "plugin version quan sát được qua readme.txt Stable tag (E5)", source_ref: "E5", observable: true, kind: build}
      p_nopriv_async_handler:
        {description: "handler async_litespeed gọi được không xác thực (wp_ajax_nopriv_async_litespeed)", source_ref: "nvd", observable: true, kind: precondition}
      p_weak_6char_hash:
        {description: "sink: litespeed.router.hash 6 ký tự sinh từ mt_rand (10^6 seed) — điều kiện config bật crawler (D-021.2) — thuộc B", source_ref: "nvd", observable: false, kind: build,
         note: "brute-force 10^6 qua HTTP ngoài budget; hash đọc từ DB = ground truth stand-in (D-021.2)"}
      p_crawler_config_on:
        {description: "crawler/role simulation bật (tiền điều kiện config)", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_forged_cookie_admin, all_of: [p_nopriv_async_handler, p_crawler_config_on],
         scope_ref: "Patchstack CVE-2024-28000"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/litespeed-cache/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "body chứa 'Stable tag:' với token version parse được — ghi nhận <ver>"
          false_when: "body chứa 'Stable tag:' nhưng không parse được version"
          ambiguity_when: "404 (readme bị chặn); plugin đổi slug; x-litespeed-* header không mang version"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["lsc_6301", "lsc_64"]
          artifact_refs: []
          note: "artifacts/28000-repro.txt là log khai thác; không dùng để chấm verified"
      - id: probe_async_handler
        request: {method: POST, path: "/wp-admin/admin-ajax.php",
                  headers: ["Content-Type: application/x-www-form-urlencoded"], body: "action=async_litespeed&litespeed_type=crawler"}
        maps_to: p_nopriv_async_handler
        interpret:
          true_when: "HTTP 200 (handler nopriv tồn tại và trả lời)"
          false_when: "HTTP 200 nhưng body KHÔNG phải phản hồi của admin-ajax (handler không thực sự trả lời)"
          ambiguity_when: "HTTP 400 với body '0'/'action not found' (không có handler nopriv HOẶC admin-ajax bị chặn); 403 do chặn admin-ajax/WAF; 200 nhưng body rỗng"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["lsc_6301", "lsc_64"]
          artifact_refs: []
      # p_weak_6char_hash, p_crawler_config_on: observable=false → không có probe
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 2 (D-021.2 chấp nhận deviation hash-từ-DB); không có ghi nhận development."
```

---

## CVE-2024-37383 — Roundcube stored XSS via SVG `<animate>` (auth)

```yaml
CVE-2024-37383:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot/CVE-2024-37383/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndExcluding, versionStartIncluding}"
        literal: "roundcube:webmail:* versionEndExcluding=1.5.7 ; 1.6.0≤v<1.6.7 (+ cpe:o:debian:debian_linux:10.0)"
      nvd:
        artifact: "data/public-snapshot/CVE-2024-37383/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[]"
        literal: "entry 1: vendor='n/a' version='n/a'; entry 2: vendor='roundcube', product='webmail', versions=[{version:'0', lessThan:'1.5.7', versionType:'semver'}] (provenance chỉ một phần là CNA)"
      advisory:
        artifact: "data/public-snapshot/CVE-2024-37383/advisory.html"
        field: "github.com/roundcube/roundcubemail/releases/tag/1.5.7 → release notes body"
        literal: "\"This is a security update to the stable version 1.5 of Roundcube Webmail. It provides a fix to a recently reported XSS vulnerabilities:\" ; \"Fix cross-site scripting (XSS) vulnerability in handling SVG animate attributes. Reported by Valentin T. and Lutz Wolf of CrowdStrike.\" ; \"This version is considered stable and we recommend to update all productive installations of Roundcube 1.5.x with it.\" (không có khối affected-range dạng bảng)"
    conditions:
      p_product_roundcube:
        {description: "target là Roundcube Webmail", source_ref: "advisory", observable: true, kind: build}
      p_version_lt_157:
        {description: "Roundcube < 1.5.7 (case: 1.5.6)", source_ref: "cpe/advisory", observable: false, kind: build,
         note: "version không quan sát được unauth (/CHANGELOG 403)"}
      p_crafted_html_mail:
        {description: "sink: thư HTML chứa <animate attributeName=\"href \" values=\"javascript:…\"> sống qua sanitizer — thuộc B", source_ref: "nvd", observable: false, kind: build}
      p_message_view_auth:
        {description: "phiên đọc mail", source_ref: "nvd", observable: false, kind: precondition}
      p_victim_click:
        {description: "victim click thật vào link đã animate", source_ref: "nvd", observable: false, kind: precondition}
    paths:
      - {id: path_click_execution, all_of: [p_message_view_auth, p_victim_click],
         scope_ref: "G5 — impact = click + thực thi JS (đường tác động DUY NHẤT); bỏ đường 'animate sống qua sanitizer' (sink thuộc B)"}
  method:
    contract:
      access_model: "auth(victim reads message; attacker đưa mail qua SMTP)"
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: probe_login_page
        request: {method: GET, path: "/?_task=login"}
        maps_to: p_product_roundcube
        interpret:
          true_when: "HTTP 200 và body chứa dấu hiệu Roundcube"
          false_when: "HTTP 200 và body là trang webmail khác (product khác)"
          ambiguity_when: "chỉ có status 200/404 → không đủ để khẳng định product"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["rc156", "rc157"]
          artifact_refs: []
      # p_version_lt_157, p_message_view_auth, p_victim_click: observable=false → không có probe
      # (observe_message_html đã BỎ theo G5/B2: nó quan sát chính sink crafted mail, không phải tiền điều kiện benign)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5→Unknown, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "Batch 4; không có ghi nhận development."
```

---

## CVE-2023-23752 — Joomla! CMS improper access check in webservice endpoints (unauth, info disclosure) — TOP-UP 2026-10-17

```yaml
CVE-2023-23752:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-23752/cpe.json"
        field: "cpe_match[] → {cpeName, versionStartIncluding, versionEndExcluding}"
        literal: "cpe:2.3:a:joomla:joomla\\!:*:*:*:*:*:*:*:* versionStartIncluding=4.0.0, versionEndExcluding=4.2.8 (vulnerable=true, 1 entry)"
      nvd:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-23752/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[] + .descriptions[0].value + configurations.nodes[].cpeMatch[]"
        literal: "Joomla! Project / 'Joomla! CMS' → versions=[{version:'4.0.0-4.2.7', status:'affected'}]; CISA-ADP (134c704f…) → {version:'4.0.0', lessThanOrEqual:'4.2.7', status:'affected'}; configurations cpeMatch: versionStartIncluding=4.0.0, versionEndExcluding=4.2.8; description: \"An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.\""
      advisory:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-23752/advisory.html"
        field: "developer.joomla.org security-centre 894 → khối header 'Versions' / 'Affected Installs' / 'Solution' / 'Exploit type'"
        literal: "\"Versions: 4.0.0-4.2.7\" ; \"Affected Installs Joomla! CMS versions 4.0.0-4.2.7\" ; \"Solution Upgrade to version 4.2.8\" ; \"Exploit type: Incorrect Access Control\""
    conditions:
      p_version_observed:
        {description: "version Joomla core quan sát được qua manifest XML tĩnh (E5) — chỉ ghi giá trị V, không so dải (G2)",
         source_ref: "E5", observable: true, kind: build}
      p_config_object_readable:
        {description: "tài nguyên `v1/config/application` thực sự được trả cho request KHÔNG xác thực (kênh disclosure đang mở) — với info-disclosure, precondition của đường tác động và quan sát lành tính trùng nhau (không vòng tròn: predicate chỉ kiểm cấu trúc JSON:API + tên key JConfig, KHÔNG đòi giá trị canary)",
         source_ref: "advisory", observable: true, kind: precondition,
         note: "True ⇒ 200 + JSON:API envelope + data[] chứa JConfig keys ⇒ impact đã quan sát được; canary-value là tiêu chí NHÃN (D-035 §4), không phải predicate method. False (401 app-level có envelope) ⇒ với B=True đường tác động bị chặn (nhánh b)."}
      p_api_entry_reachable:
        {description: "entry API `/api/index.php` trả lời request không xác thực bằng JSON:API envelope của Joomla (route tồn tại, không cần SEF/rewrite)",
         source_ref: "nvd/advisory", observable: true, kind: precondition,
         note: "BỊ BAO HÀM bởi p_config_object_readable: một envelope JSON:API từ /api/index.php đã chứng minh entry reachable ⇒ rút khỏi paths.all_of (phán quyết #3). Giữ làm mô tả; KHÔNG có probe riêng (không tăng budget)."}
      p_webservices_config_enabled:
        {description: "plugin `plg_webservices_config` enabled ⇒ route `v1/config/application` được đăng ký",
         source_ref: "advisory/nvd", observable: false, kind: precondition,
         note: "BỊ BAO HÀM: route trả JConfig ⇒ plugin đã bật ⇒ rút khỏi paths.all_of (phán quyết #3). Không có tín hiệu HTTP trực tiếp phân biệt được ⇒ KHÔNG tạo probe giả (R2)."}
      p_public_query_override:
        {description: "sink: `ApiRouter::parseApiRoute()` để key `public` từ query ghi đè default `public => false` của route (bản vá 4.2.8 unset key này) — thuộc B (version-determined)",
         source_ref: "nvd / fix-diff", observable: false, kind: build}
    paths:
      - {id: path_unauth_config_disclosure,
         all_of: [p_config_object_readable],
         scope_ref: "Joomla Security Centre [20230201] (CVE-2023-23752)"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_joomla_version
        request: {method: GET, path: "/administrator/manifests/files/joomla.xml"}
        maps_to: p_version_observed
        interpret:
          true_when: "HTTP 200 và body parse được thành XML có phần tử `<version>` chứa token version Joomla (vd '4.2.7') — ghi nhận <ver>; KHÔNG so với dải ở đây (G2)"
          false_when: "HTTP 200, XML parse được nhưng `<version>` thiếu/rỗng"
          ambiguity_when: "404/403 (file bị xoá/bị chặn — vắng mặt bằng chứng, KHÔNG phải 'ngoài dải', G3); trả HTML/trang lỗi thay vì XML; có chuỗi version nhưng không parse được"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["jl427_default", "jl428_default"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-joomla.xml.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-joomla.xml.raw.txt"]
          note: "verified (capture 2026-10-17): 200 `Content-Type: application/xml`, 1,556 B, unauth; `<version>4.2.7</version>` (427) vs `<version>4.2.8</version>` (428). `GET /language/en-GB/langmetadata.xml` 200 `<version>4.2.7</version>` là quan sát THAY THẾ, chỉ ghi chú — KHÔNG đưa vào contract (phán quyết #1: giữ 1 request, không tăng budget)."
      - id: probe_config_application_public
        request: {method: GET, path: "/api/index.php/v1/config/application?public=true"}
        maps_to: p_config_object_readable
        interpret:
          true_when: "HTTP 200 với `Content-Type: application/vnd.api+json` và body có `data[]` mà `attributes` chứa các key cấu hình toàn cục đọc từ `configuration.php` (tối thiểu `dbprefix`, `sitename`, `host`, `user`) — tức object global-config được trả cho request không xác thực; GHI NHẬN THÊM có/không các key mang bí mật (`password`, `secret`) nhưng KHÔNG đòi khớp giá trị canary"
          false_when: "HTTP 401 kèm JSON:API error envelope của Joomla `{\"errors\":[{\"title\":\"Forbidden\"}]}` và `X-Powered-By: JoomlaAPI/1.0` (tài nguyên trả lời và từ chối request không xác thực — từ chối cụ thể ở tầng ứng dụng, không phải 403/404 trần)"
          ambiguity_when: "401/403/404 trần KHÔNG có envelope JSON:API (proxy/WAF/REST bị chặn toàn cục; 404 cũng có thể là `plg_webservices_config` tắt ⇒ route không đăng ký — KHÔNG kết luận False, G3); 200 nhưng body HTML (rơi về front-end/SEF) hoặc `data[]` rỗng/thiếu key JConfig; 500 (lỗi ứng dụng, vd DB down); redirect tới trang đăng nhập"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["jl427_default", "jl428_default"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-api-config-application_public-true.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-api-config-application_public-true.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-api-config-application_NO-public-param.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-api-config-application_NO-public-param.raw.txt"]
          note: "verified (capture 2026-10-17): 427 → 200, `Content-Type: application/vnd.api+json`, 2,011 B, `data[]` có `dbprefix`/`sitename`/`host`/`user` + `\"password\":\"RQ-C1-CANARY-23752-DBPASS-427\"` + `meta.total-pages=4`; 428 → 401 `{\"errors\":[{\"title\":\"Forbidden\"}]}` (34 B), canary vắng. Control cơ chế (bỏ `?public=true`) → 401 trên CẢ HAI build — giữ làm VALIDATION EVIDENCE, KHÔNG thành probe runtime (phán quyết #4: 401 trên cả 2 build, không phân biệt affected/fixed)."
      # p_api_entry_reachable / p_webservices_config_enabled: bị bao hàm, rút khỏi path (phán quyết #3) → không có probe riêng
      # p_public_query_override: B (version-determined) → không có probe; không nằm trong paths (G1)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "CVE thêm sau V1/V2 (D-035, 2026-10-17); không được dùng để phát triển rule hay signal. Không suy ra held-out một cách tự động (spec §5)."
```

---

## CVE-2023-6553 — WP plugin Backup Migration ≤ 1.3.7, unauth RCE qua `includes/backup-heart.php` — TOP-UP 2026-10-17

```yaml
CVE-2023-6553:
  reference:
    ranges_by_source:
      cpe:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-6553/cpe.json"
        field: "cpe_match[] → {cpeName, versionEndIncluding}"
        literal: "cpe:2.3:a:backupbliss:backup_migration:*:*:*:*:*:wordpress:*:* versionEndIncluding=1.3.7 (vulnerable=true, 1 entry)"
      nvd:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-6553/nvd.json"
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[] + .descriptions[0].value"
        literal: "vendor='inisev', product='BackupBliss – Backup & Migration with Free Cloud Storage', versions=[{version:'0', lessThanOrEqual:'1.3.7', versionType:'semver', status:'affected'}]; description: \"… vulnerable to Remote Code Execution in all versions up to, and including, 1.3.7 via the /includes/backup-heart.php file.\" — NVD KHÔNG nêu fixed version"
      advisory:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-6553/advisory-fallback.json (primary = advisory-primary.error.txt: WPScan HTTP 403 JS challenge; Wordfence HTTP 202, 0 B, không persist)"
        field: "containers.cna.affected[0].versions[] + containers.cna.title + containers.cna.descriptions[0].value (CVE.org 5.2 CNA record, assigner Wordfence, state PUBLISHED)"
        literal: "\"Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution\" ; affected: version '0', lessThanOrEqual '1.3.7', versionType 'semver', status 'affected' ; \"This is due to an attacker being able to control the values passed to an include, and subsequently leverage that to achieve remote code execution.\" — CVE.org/NVD KHÔNG nêu fixed version; **1.3.8 chỉ đến từ gói 1.3.8** (readme changelog `= 1.3.8 =` / `* [FIX] Patched reported CVE - please upgrade` trong `downloads/bb-1.3.8.zip` + `filterChainFix()`, `experiments/topup-2026-10-17/fix-diff.md` §2 — provenance của fixed version, không phải của range)"
    conditions:
      p_version_observed:
        {description: "version plugin quan sát được qua `readme.txt` → `Stable tag` (E5)",
         source_ref: "E5", observable: true, kind: build}
      p_plugin_files_present:
        {description: "`includes/backup-heart.php` có mặt trong `wp-content/plugins/backup-backup/` và truy cập được bằng URL trực tiếp (files installed — activation không cần)",
         source_ref: "nvd/advisory + D-036", observable: true, kind: precondition,
         note: "đo 2026-10-17: file trả lời ở cả trạng thái active và inactive ⇒ 'installed is enough' (D-036). ĐÂY LÀ PRECONDITION DUY NHẤT của path (phán quyết #6)."}
      p_plugin_active:
        {description: "plugin được kích hoạt trong WordPress",
         source_ref: "nvd/advisory", observable: false, kind: precondition,
         note: "**KHÔNG nằm trong path nào.** Đo 2026-10-17: deactivate KHÔNG chặn entry point (D-036) ⇒ 'active' không phải precondition và KHÔNG có nhánh-b qua deactivation. Giữ entry chỉ để chặn việc dùng nó làm điều kiện gate."}
      p_sink_unsanitised_include:
        {description: "sink: 1.3.7 đưa `Content-Dir` của client vào `BMI_INCLUDES` rồi `require_once`; 1.3.8 `filterChainFix()` từ chối giá trị chứa `php:`, pipe, >256 ký tự — thuộc B (version-determined)",
         source_ref: "nvd / fix-diff", observable: false, kind: build}
      p_php_filter_wrapper:
        {description: "runtime resolve được stream `php://filter/` trong `require_once` (iconv + filter wrapper bật) — gadget khai thác / thuộc tính runtime, KHÔNG phải precondition triển khai",
         source_ref: "nvd/fix-diff", observable: false, kind: build,
         note: "RÚT KHỎI paths.all_of (phán quyết #6): 'gadget có bắn hay không' là mức 3 (reproduce = ground truth; method không trả lời, D-008). Giữ làm mô tả (kind: build = không phải precondition); không có probe — phân biệt nó đòi hỏi gửi chính filter-chain, tức là exploit."}
    paths:
      - {id: path_direct_file_filter_chain,
         all_of: [p_plugin_files_present],
         scope_ref: "CVE.org CNA record (Wordfence) / NVD CVE-2023-6553"}
  method:
    contract:
      access_model: unauth
      max_requests_per_case: 20
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_plugin_readme_version
        request: {method: GET, path: "/wp-content/plugins/backup-backup/readme.txt"}
        maps_to: p_version_observed
        interpret:
          true_when: "HTTP 200, body text chứa `Stable tag:` với token version parse được — ghi nhận <ver> (không so dải, G2)"
          false_when: "HTTP 200, body chứa `Stable tag:` nhưng giá trị không parse được thành version"
          ambiguity_when: "404/403 (readme bị xoá/chặn — G3); trả HTML thay vì text; `Stable tag` thiếu hoặc là placeholder"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["bb137_active", "bb137_inactive", "bb138_active"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/plugin-readme-137.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/version-observability-138.raw.txt"]
          note: "verified (capture 2026-10-17): 1.3.7 → 200 `Content-Type: text/plain`, `Stable tag: 1.3.7`; 1.3.8 → 200, `Stable tag: 1.3.8`. LƯU Ý: capture 1.3.7 bị cắt ở 32,512 B (Content-Length 46,630) — dòng `Stable tag` nằm trong phần đầu nên predicate vẫn đọc được, nhưng bản capture KHÔNG phải toàn bộ body. Trạng thái 1.3.7 **inactive** dùng chung capture readme của 1.3.7 active: `readme.txt` là file tĩnh và case README §6 ghi state a/b chung một cột (`wp plugin deactivate` không sửa file plugin; registry: 'directory untouched') — ghi nhận là tái dùng artifact, không phải capture riêng."
      - id: probe_direct_file_reachable
        request:
          method: POST
          path: "/wp-content/plugins/backup-backup/includes/backup-heart.php"
          headers: ["Content-Dir: /var/www/html/wp-content/plugins/backup-backup/",
                    "Content-Abs: /var/www/html",
                    "Content-Content: /var/www/html/wp-content/",
                    "Content-Configdir: /var/www/html/wp-content/backup-backup-config",
                    "Content-Backups: /var/www/html/wp-content/backup-backup-backups",
                    "Content-Url: http://<target>",
                    "Content-Identy: rq-c1",
                    "Content-Manifest: ",
                    "Content-Safelimit: 128",
                    "Content-Rev: 1",
                    "Content-Name: rq-c1",
                    "Content-Start: 0",
                    "Content-Filessofar: 0",
                    "Content-Total: 0",
                    "Content-Bmitmp: /tmp",
                    "Content-It: 0",
                    "Content-Dbit: 0",
                    "Content-Dblast: 0"]
        maps_to: p_plugin_files_present
        interpret:
          true_when: "HTTP 200 với body RỖNG 0 byte — một file PHP tại đúng path đó ĐÃ thực thi và bỏ output; `Content-Dir` benign trỏ vào thư mục plugin thật, KHÔNG chứa filter chain, KHÔNG ghi marker (đo 2026-10-17 trên cả 3 state)"
          ambiguity_when: "404/403 với trang lỗi Apache/nginx (file thiếu HAY direct access bị chặn — không phân biệt được); **200 + body là trang WordPress/front-page (rewrite) = dấu hiệu file VẮNG, KHÔNG phải 404** (control `d-137-nonexistent-path-absent-file.raw.txt`: path không tồn tại → 200 + 49,717 B trang chủ); 500 (file chạy nhưng die, vd thiếu header); 200 với body PHP-error không rỗng; response của WAF/rate-limit"
          otherwise: Unknown
        validation:
          status: verified
          control_state_ids: ["bb137_active", "bb137_inactive", "bb138_active"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/d-137-active-benign-include.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/d-137-inactive-benign-include.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/c-138-active-benign-include-control.raw.txt"]
          note: "verified (capture 2026-10-17): cả 3 state → HTTP 200 + 0 B (1.3.7 active 0.004 s, 1.3.7 inactive 0.003 s, 1.3.8 control 0.007 s); marker absent trong cả 3 (xem `d-137-benign-marker-checks.txt`). ONE-SIDED theo phán quyết #7: KHÔNG có `false_when` ⇒ file vắng/bị chặn → Unknown, KHÔNG có nhánh-b cho CVE này. Các capture filter-chain (`a-*`, `b-*`, `c-138-active-POST-filterchain`) là log khai thác, KHÔNG dùng để chấm verified."
      # p_plugin_active: observable=false và KHÔNG trong path (đo được là không phải điều kiện)
      # p_php_filter_wrapper: rút khỏi path (phán quyết #6), observable=false → không có probe
      # p_sink_unsanitised_include: B (version-determined) → không probe, không nằm trong paths (G1)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "CVE thêm sau V1/V2 (D-035, 2026-10-17); không được dùng để phát triển rule hay signal. Không suy ra held-out một cách tự động (spec §5)."
```

---

## Open items / gaps

### A. Probe status tổng hợp (đếm theo CVE — chi tiết ở mỗi section)

| CVE | verified | pending | needs_control | Điều kiện `observable: false` (không có probe) |
|---|---|---|---|---|
| CVE-2014-3704 | 1 | 1 | 0 | 2 |
| CVE-2015-3440 | 1 | 1 | 0 | 1 |
| CVE-2017-1001000 | 2 | 0 | 0 | 1 |
| CVE-2018-7600 | 1 | 1 | 0 | 2 |
| CVE-2018-7602 | 0 | 2 | 0 | 2 |
| CVE-2019-10692 | 0 | 2 | 0 | 1 |
| CVE-2019-6340 | 0 | 2 | 1 | 3 |
| CVE-2019-6341 | 1 | 1 | 0 | 3 |
| CVE-2019-8942 | 1 | 0 | 1 | 3 |
| CVE-2020-12625 | 0 | 1 | 0 | 4 |
| CVE-2020-12640 | 0 | 2 | 0 | 3 |
| CVE-2020-12641 | 0 | 2 | 0 | 2 |
| CVE-2020-13671 | 1 | 0 | 0 | 4 |
| CVE-2020-25213 | 0 | 2 | 0 | 1 |
| CVE-2021-23017 | 0 | 1 | 0 | 1 |
| CVE-2021-24917 | 0 | 2 | 0 | 1 |
| CVE-2021-29447 | 2 | 0 | 1 | 3 |
| CVE-2021-41773 | 1 | 0 | 0 | 2 |
| CVE-2021-42013 | 1 | 0 | 0 | 2 |
| CVE-2021-44026 | 0 | 1 | 0 | 4 |
| CVE-2022-21661 | 2 | 1 | 0 | 1 |
| CVE-2023-2745 | 1 | 0 | 0 | 2 |
| CVE-2023-28121 | 0 | 2 | 0 | 1 |
| CVE-2023-32243 | 0 | 3 | 0 | 1 |
| CVE-2023-3460 | 2 | 0 | 0 | 1 |
| CVE-2023-5631 | 0 | 1 | 0 | 4 |
| CVE-2023-5798 | 1 | 0 | 1 | 4 |
| CVE-2024-10924 | 3 | 0 | 0 | 0 |
| CVE-2024-28000 | 0 | 2 | 0 | 2 |
| CVE-2024-37383 | 0 | 1 | 0 | 4 |
| CVE-2023-23752 (top-up) | 2 | 0 | 0 | 2 |
| CVE-2023-6553 (top-up) | 2 | 0 | 0 | 3 |
| **TỔNG** | **25** | **31** | **4** | **70** |

> Tổng probe = **60** (25 verified + 31 pending + 4 needs_control). Bảng này được **đếm lại từ chính file** ở lượt top-up
> 2026-10-17: bản trước còn ghi 18/34/4 vì chưa cập nhật D-032 (hạ `probe_rest_root`) và D-034 (nâng 4 probe V2) — chỉ sửa
> dòng thống kê, không đổi probe nào. Sau lượt sửa bước 2 (bỏ 4 probe sink: 24917-referer, 2745-reflection,
> 5631/37383 message-HTML; hạ 23017 verified→pending) **và lượt top-up 2026-10-17** (thêm 4 probe đều
> `verified`: 23752 `observe_joomla_version` + `probe_config_application_public`; 6553 `observe_plugin_readme_version` +
> `probe_direct_file_reachable` — theo capture 2026-10-17). Không có probe nào được chấm `verified` bằng log
> PoC / DB log / attacker listener / browser harness / `dpkg -l` / image tag.

### B. Việc chưa quyết / cần researcher

1. **CVE-2021-23017 — `verified` với MỘT trạng thái.** → **ĐÃ XỬ (G6):** hạ xuống `pending`. Tách E5 (header chuỗi
   quan sát được) khỏi E4 (không phân biệt được build vá); probe chỉ chứng minh E5, chưa đủ control → pending.
2. **`pending` nhưng artifact reproduction trùng hình dạng probe.** Các case sau có file repro ghi lại **đúng request + response
   cho cả hai trạng thái**, nhưng file là "reproduction log" nên bị để `pending` theo luật hai tầng:
   - CVE-2021-24917 (`24917-repro.txt`: 302 + Location `rqsecret` vs `?404`)
   - CVE-2019-10692, CVE-2019-8942 (login), CVE-2020-12640/12641 (installer), CVE-2021-44026 (message view), CVE-2023-5631 / CVE-2024-37383 (message HTML sanitizer).
   → **ĐÃ XỬ (G3/G5 + B2):** không chấp nhận theo nhóm. Các "probe" thực chất là khai thác sink đã bị **bỏ** (24917-referer,
   2745-reflection, 5631/37383 message-HTML) và condition tương ứng chuyển `kind: build` (observable:false). Các case login/
   installer/message-view còn lại giữ `pending` (chưa có capture benign đúng contract).
3. **Đường dẫn artifact không chuẩn.** Pilot 41773 để capture ở **gốc case dir** (`experiments/reproduce-cve-2021-41773/03-*.txt`),
   không nằm trong `artifacts/`. Đã ghi rõ ở probe; nếu freeze yêu cầu `artifacts/` thì cần di chuyển/đổi tên (không thực hiện ở bước này).
4. **CVE-2019-8942 & CVE-2022-21661 — cờ `used_for_signal_development`.** Được đặt `true` vì Batch 0 là "de-risk probe" và
   selection-log/README ghi nhận tường minh finding observability (author role không quan sát được; fixture asset quan sát được;
   HTTP 500 không phân biệt). Nếu researcher muốn chỉ giữ 29447/23017/5798 là signal-development thì hạ hai cờ này.
5. **CVE-2019-6340 — probe route phủ một cực.** `probe_rest_route` / `probe_jsonapi_route` bị để `pending` vì artifact
   `pilot-3cve/artifacts/http-verification.txt` chỉ ghi REST **bật** và JSON:API **tắt** cho cả hai deployment; cực đối lập
   (REST tắt 403 / JSON:API bật 200) chỉ có trong bảng README §3, không có capture thô. → cần lệnh lại hoặc chấp nhận README §3.
6. **CVE-2023-5631 — mâu thuẫn NVD ↔ CPE về dải.** NVD `affected` ghi `1.6.0 <1.6.3`, `1.5.0 <1.5.4`, `1.4.0 <1.5.14` (+ unaffected 1.6.4/1.5.5);
   CPE ghi `versionEndExcluding` 1.6.4 / 1.5.5 / 1.4.15. Advisory chỉ nêu fixed 1.6.4 (nhánh 1.6). Đây là ví dụ thật của
   §4.2 (conflict theo phạm vi) cần xử ở tầng rule, chưa xử ở đây.
7. **Advisory không có dải máy đọc được** → `.advisory` ghi `Unknown` kèm trích nguyên văn: CVE-2019-8942 (trang blog Sonar
   không còn nội dung bài), CVE-2019-10692 (trang plugin không nhắc 7.11.x), CVE-2021-44026 (trang commit GitHub),
   CVE-2020-25213 & CVE-2024-10924 (advisory primary bot-chặn → fallback vendor chỉ có changelog). Các case này Advisory-only
   sẽ trả `Unknown` ở mức 1 (đúng thiết kế §4.3), không suy thành Not Applicable.
8. **`ranges_by_source.nvd` dư thừa với `.cpe`.** Nhiều CVE có `affected_raw` kiểu `n/a` (Red Hat/MITRE) → NVD không có câu
   affected-version riêng; dải duy nhất nằm ở `configurations` (chính là nguồn của `cpe.json`). Đã ghi rõ tại từng entry
   (không bịa khác biệt — R1/D-017). Danh sách `n/a`: 2014-3704, 2015-3440, 2017-1001000, 2019-10692, 2019-8942, 2020-12625,
   2020-12640, 2020-12641, 2020-25213, 2021-44026, 2024-37383 (một phần).
9. **CPE không product-scoped (spec §4.1).** CVE-2021-23017 (25 entry; chỉ 1 là nginx), CVE-2022-21661 & CVE-2023-2745
   (22–27 entry nhiều nhánh WordPress), CVE-2021-41773/42013 (nhiều vendor thứ ba). CPE-only/NVD-only phải nhận diện product
   từ HTTP (E5) rồi lọc CPE theo đúng product trước khi so version — đã phản ánh trong `conditions`.
10. **CVE exact-version, không range** (spec §4.2): CVE-2017-1001000 (4.7/4.7.1/4.7.2 đều vulnerable=true — lưu ý 4.7.2
    *cũng* bị đánh dấu vulnerable trong CPE dù là bản vá theo advisory/registry), CVE-2021-41773, CVE-2021-42013,
    CVE-2023-2745 (`wordpress:6.2`). Luật CPE phải xử cả `versionStart/End` lẫn exact `==` — đã ghi literal.
    **CVE-2017-1001000 là mâu thuẫn CPE↔advisory cần researcher xử** (registry ghi 4.7.0–4.7.1, fixed 4.7.2).
11. **Case không có "Precondition table" đầy đủ trong README.** Các case pilot (41773, 6340, 10924, 12625) dùng bảng
    precondition nằm trong **spec/methodology** và README pilot (không có mục "Precondition table" riêng như 26 case lab);
    đã lấy điều kiện từ README pilot §3/§7 + `notes/lab-spec-26-cve-2026-10-10.md`. **CVE-2018-7602** có bảng nhưng
    artifact không có capture HTTP; **CVE-2020-35489 / CVE-2021-24284 / CVE-2024-27956** không thuộc 30 CVE canonical
    (đã drop/replace) nên không có section.
12. **`E3`/`E6` có mặt nhưng thiếu artifact.** Với nhiều case (28121 `p_woocommerce_active`, 32243 `p_elementor_active`,
    các probe `readme.txt` của plugin), điều kiện **quan sát được trên lý thuyết** nhưng **không có file capture** →
    giữ `pending`/ghi trong `observable`-note, không tạo artifact giả.
13. **Chưa chấm `verified` cho bất kỳ probe "impact path" nào** — đúng chủ trương: probe chỉ validate trạng thái predicate
    (E5/E6), không validate nhãn CVE (R3). Do đó toàn bộ case vẫn cần tầng rule (B/P_i) quyết định Applicable/Not/Unknown.
14. **ĐÃ KHÓA (bước 2 hoàn tất).** Sau khi sửa logic theo bảng phán quyết
    `reviews/Review_buoc2_mapping_phanquyet_2026-10-14.md` (G1–G7), file này được khoá kèm version + hash (xem header,
    D-030). Snapshot `data/public-snapshot/` và nhãn chuẩn giữ nguyên.
15. **Top-up 2026-10-17 — đã merge, CHỜ FREEZE (D-037).** 2 section CVE-2023-23752 / CVE-2023-6553 được thêm sau V1/V2
    theo `reviews/Review_mapping_topup_phanquyet_2026-10-17.md` (10 phán quyết đã áp: 1 request version cho 23752;
    predicate disclosure không đòi canary; path 23752 = `[p_config_object_readable]`; control no-public = validation
    evidence; reachability 6553 = POST benign; `p_php_filter_wrapper` rút khỏi path; one-sided, không nhánh-b;
    advisory 6553 parse JSON CVE.org + provenance fixed 1.3.8; merge vào file này; loader nhận cohort snapshot thứ hai).
    Nhãn là D-036 (không đổi ở đây). **Bản 32-CVE chưa có hash freeze — D-037 là bước kế tiếp; mọi thống kê probe
    phía trên đã tính 2 CVE này.**
