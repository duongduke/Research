# Collector/mapping DRAFT — 2 CVE top-up (2026-10-17) — CHƯA KHÓA

> **Trạng thái: DRAFT để researcher review.** Chưa phải mapping đã duyệt, chưa freeze, chưa có hash.
> Không có probe nào được đánh dấu `verified` ở đây — **mọi** `validation.status = pending`; researcher
> sẽ đối chiếu capture rồi tự nâng/hạ (D-028 R3, G7).
>
> Phạm vi: 2 CVE ID mới của **D-035**, nhãn đã được chấp nhận ở **D-036**
> (CVE-2023-23752: 4.2.7 Applicable / 4.2.8 Not Applicable a; CVE-2023-6553: 1.3.7 active + 1.3.7
> inactive Applicable / 1.3.8 Not Applicable a).
>
> Schema: `notes/collector-mapping-spec-2026-10-11.md` §2 + các quy ước bổ sung của bản 30-CVE
> (`notes/collector-mapping-30cve.md`, phần "Quy ước bổ sung"): `literal:`, `kind: build|precondition`,
> `observable:`, `scope_ref`, probe POST có `request.body`/`headers`. Phán quyết đang áp: **G1** (path chỉ
> chứa precondition), **G2** (version probe trung lập, không cutoff), **G3** (không 403/404 trần → False),
> **G7** (pending → Unknown ở runtime). **G5** không áp dụng (không có XSS ở 2 CVE này).
>
> Nguồn điền:
> - snapshot cohort riêng `data/public-snapshot-2026-10-17/<CVE>/{nvd.json,cpe.json,advisory*}` (fetch 2026-10-17);
> - nhãn + precondition: `experiments/26cve/registry.md` **Appendix F** (+ `experiments/26cve/selection-log.md`
>   mục "Top-up (2026-10-17, D-035/D-036)");
> - capture lab: `experiments/topup-2026-10-17/cases/<CVE>/artifacts/` (+ `README.md` từng case);
> - cơ chế/bản vá: `notes/cve-verification-topup-2026-10-17.md`, `experiments/topup-2026-10-17/fix-diff.md`.
>
> **Không** sửa `notes/collector-mapping-30cve.md`, không sửa snapshot, không chạy lại benchmark, không
> regenerate input, không gửi request nào trong phiên này. Mọi giá trị HTTP dưới đây là **trích từ capture
> đã có**, không phải kết quả mới.

---

## CVE-2023-23752 — Joomla! CMS, improper access check in webservice endpoints (unauth, info disclosure)

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
        field: "vulnerabilities[0].cve.affected[].affectedData[].versions[] + .descriptions[0].value"
        literal: "Joomla! Project / 'Joomla! CMS' → versions=[{version:'4.0.0-4.2.7', status:'affected'}]; CISA-ADP (134c704f…) → {version:'4.0.0', lessThanOrEqual:'4.2.7'}; description: \"An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.\""
      advisory:
        artifact: "data/public-snapshot-2026-10-17/CVE-2023-23752/advisory.html"
        field: "developer.joomla.org security-centre 894 → khối header 'Versions' / 'Affected Installs' / 'Solution'"
        literal: "\"Versions: 4.0.0-4.2.7\" ; \"Affected Installs Joomla! CMS versions 4.0.0-4.2.7\" ; \"Solution Upgrade to version 4.2.8\" ; \"Exploit type: Incorrect Access Control\""
    conditions:
      p_version_observed:
        {description: "version Joomla core quan sát được qua manifest XML tĩnh (E5) — chỉ ghi giá trị V, không so dải (G2)",
         source_ref: "E5", observable: true, kind: build}
      p_api_entry_reachable:
        {description: "entry API `/api/index.php` trả lời request không xác thực bằng JSON:API envelope của Joomla (route tồn tại, không cần SEF/rewrite)",
         source_ref: "nvd/advisory", observable: true, kind: precondition,
         note: "quan sát được từ chính response của probe disclosure (R4: 2 extraction trên 1 response = 1 request)"}
      p_webservices_config_enabled:
        {description: "plugin `plg_webservices_config` enabled ⇒ route `v1/config/application` được đăng ký",
         source_ref: "advisory/nvd", observable: false, kind: precondition,
         note: "không có tín hiệu HTTP trực tiếp; fixture mặc định bật cả 17 webservices plugin ⇒ chỉ suy ra gián tiếp từ hành vi route; KHÔNG tạo probe giả (R2)"}
      p_config_object_readable:
        {description: "tài nguyên `v1/config/application` thực sự được trả cho request KHÔNG xác thực (kênh disclosure đang mở) — precondition ở mức impact, tách khỏi version",
         source_ref: "advisory", observable: true, kind: precondition,
         note: "False (bị từ chối) ⇒ với B=True thì đường tác động bị chặn (nhánh b); True ⇒ impact đã quan sát được"}
      p_public_query_override:
        {description: "sink: `ApiRouter::parseApiRoute()` để key `public` từ query ghi đè default `public => false` của route (bản vá 4.2.8 unset key này) — thuộc B",
         source_ref: "nvd / fix-diff", observable: false, kind: build}
    paths:
      - {id: path_unauth_config_disclosure,
         all_of: [p_api_entry_reachable, p_webservices_config_enabled, p_config_object_readable],
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
          status: pending
          control_state_ids: ["jl427_default", "jl428_default"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-joomla.xml.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-joomla.xml.raw.txt"]
          note: "capture: 200 `Content-Type: application/xml`, 1,556 B, unauth; `<version>4.2.7</version>` (427) vs `<version>4.2.8</version>` (428). Quan sát thay thế cùng giá trị: `GET /language/en-GB/langmetadata.xml` 200, `<version>4.2.7</version>` → xem Open design point 1. Chưa verified: cần researcher phán quyết (control dương/âm đã có, nhưng đây là lần điền đầu)."
      - id: probe_config_application_public
        request: {method: GET, path: "/api/index.php/v1/config/application?public=true"}
        maps_to: p_config_object_readable        # đồng thời suy ra p_api_entry_reachable từ cùng response
        interpret:
          true_when: "HTTP 200 với `Content-Type: application/vnd.api+json` và body có `data[]` mà `attributes` chứa các key cấu hình toàn cục đọc từ `configuration.php` (vd `dbprefix`, `sitename`, `host`, `user`) — tức object global-config được trả cho request không xác thực; ghi nhận thêm có/không các key mang bí mật (`password`, `secret`, `mailfrom`)"
          false_when: "HTTP 401 kèm JSON:API error envelope của Joomla `{\"errors\":[{\"title\":\"Forbidden\"}]}` và `X-Powered-By: JoomlaAPI/1.0` (tài nguyên trả lời và từ chối request không xác thực — đây là từ chối cụ thể ở tầng ứng dụng, không phải 403/404 trần)"
          ambiguity_when: "401/403/404 trần KHÔNG có envelope JSON:API (proxy/WAF/REST bị chặn toàn cục; 404 cũng có thể là `plg_webservices_config` tắt ⇒ route không đăng ký — KHÔNG kết luận False, G3); 200 nhưng body HTML (rơi về front-end/SEF) hoặc `data[]` rỗng; 500 (lỗi ứng dụng, vd DB down); redirect tới trang đăng nhập"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["jl427_default", "jl428_default"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-api-config-application_public-true.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-api-config-application_public-true.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-api-config-application_NO-public-param.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-api-config-application_NO-public-param.raw.txt"]
          note: "capture: 427 → 200, 2,011 B, 65 key/4 trang, có `\"password\":\"RQ-C1-CANARY-23752-DBPASS-427\"` + `\"secret\":\"RQ-C1-CANARY-23752-SECRET-427\"`, `meta.total-pages=4`; 428 → 401 `{\"errors\":[{\"title\":\"Forbidden\"}]}` (34 B), canary vắng. Control cơ chế (không `?public=true`) → 401 trên CẢ HAI build. Chỉ trang 1 (offset 0) là đủ cho predicate; 3 trang còn lại là impact evidence, không cần cho probe."
      # p_webservices_config_enabled: observable=false → không có probe khẳng định
      # p_public_query_override: B (version-determined) → không có probe; không nằm trong paths (G1)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "CVE thêm sau V1/V2 (D-035, 2026-10-17); không được dùng để phát triển rule hay signal. Không suy ra held-out một cách tự động (spec §5)."
```

---

## CVE-2023-6553 — WP plugin Backup Migration ≤ 1.3.7, unauth RCE qua `includes/backup-heart.php`

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
        field: "containers.cna.affected[0].versions[] + containers.cna.title + containers.cna.descriptions[0].value"
        literal: "\"Backup Migration <= 1.3.7 - Unauthenticated Remote Code Execution\" ; affected: version '0', lessThanOrEqual '1.3.7', versionType 'semver', status 'affected' ; \"This is due to an attacker being able to control the values passed to an include, and subsequently leverage that to achieve remote code execution.\" — CVE.org/NVD KHÔNG nêu fixed version; **1.3.8 chỉ đến từ gói 1.3.8** (readme changelog `= 1.3.8 =` / `* [FIX] Patched reported CVE - please upgrade` (verified in `downloads/bb-1.3.8.zip`) + `filterChainFix()`, `experiments/topup-2026-10-17/fix-diff.md` §2)"
    conditions:
      p_version_observed:
        {description: "version plugin quan sát được qua `readme.txt` → `Stable tag` (E5)",
         source_ref: "E5", observable: true, kind: build}
      p_plugin_files_present:
        {description: "`includes/backup-heart.php` có mặt trong `wp-content/plugins/backup-backup/` và truy cập được bằng URL trực tiếp (files installed — activation không cần)",
         source_ref: "nvd/advisory + D-036", observable: true, kind: precondition,
         note: "đo được: file trả lời ở cả trạng thái active và inactive (2026-10-17)"}
      p_plugin_active:
        {description: "plugin được kích hoạt trong WordPress",
         source_ref: "nvd/advisory", observable: false, kind: precondition,
         note: "**KHÔNG nằm trong path nào.** Đo 2026-10-17: deactivate KHÔNG chặn entry point (D-036) ⇒ 'active' không phải precondition và KHÔNG có nhánh-b qua deactivation. Giữ entry này chỉ để chặn việc dùng nó làm điều kiện gate."}
      p_php_filter_wrapper:
        {description: "runtime resolve được stream `php://filter/` trong `require_once` (iconv + filter wrapper bật)",
         source_ref: "nvd/fix-diff", observable: false, kind: precondition,
         note: "không probe được bằng cách không-khai-thác: phân biệt nó đòi hỏi gửi chính chuỗi filter-chain (tức là exploit). Vì vậy observable=false ⇒ trung thực là Unknown, không phải False; xem Open design point 6 (đây là điểm quyết định liệu fusion có bao giờ kết luận được Applicable cho CVE này)."}
      p_sink_unsanitised_include:
        {description: "sink: 1.3.7 đưa `Content-Dir` của client vào `BMI_INCLUDES` rồi `require_once`; 1.3.8 `filterChainFix()` từ chối giá trị chứa `php:`, pipe, >256 ký tự — thuộc B",
         source_ref: "nvd / fix-diff", observable: false, kind: build}
    paths:
      - {id: path_direct_file_filter_chain,
         all_of: [p_plugin_files_present, p_php_filter_wrapper],
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
          status: pending
          control_state_ids: ["bb137_active", "bb137_inactive", "bb138_active"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/plugin-readme-137.raw.txt",
                          "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/version-observability-138.raw.txt"]
          note: "capture: 1.3.7 active → 200, `Content-Type: text/plain`, `Stable tag: 1.3.7`; 1.3.8 active → 200, `Stable tag: 1.3.8`. LƯU Ý: file capture 1.3.7 bị cắt ở 32,512 B (Content-Length 46,630) — dòng `Stable tag` nằm trong phần đầu nên predicate vẫn đọc được, nhưng bản capture KHÔNG phải toàn bộ body; trạng thái inactive không được capture riêng (files không đổi ⇒ kỳ vọng giống, chưa đo) → xem Open design point 5."
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
          true_when: "HTTP 200 với `Content-Length: 0` (hoặc body `Incorrect parameters.` ở ≥1.3.8) — một file PHP tại đúng path đó ĐÃ thực thi và bỏ output; `Content-Dir` benign trỏ vào thư mục plugin thật, KHÔNG chứa filter chain, KHÔNG ghi marker"
          false_when: "không có false_when dương an toàn: 404 trần không dùng được (proxy/WAF/rule chặn direct-PHP đều có thể tạo 404) — xem ambiguity_when (G3)"
          ambiguity_when: "404/403 với trang lỗi Apache/nginx (file thiếu HAY direct access bị chặn — không phân biệt được); 500 (file chạy nhưng die, vd thiếu header); 200 với body HTML/PHP-error không rỗng (có thể từ error handler); response của WAF/rate-limit"
          otherwise: Unknown
        validation:
          status: pending
          control_state_ids: ["bb137_active", "bb137_inactive", "bb138_active"]
          artifact_refs: ["experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/c-138-active-benign-include-control.raw.txt"]
          note: "Benign control MỚI chỉ có cho 1.3.8 (200, 0 B, marker absent). Capture 1.3.7 hiện có là **PoC filter-chain** (`a-…`, `b-…`) ⇒ log khai thác, KHÔNG dùng để chấm verified (D-015). Vì vậy probe này **pending** dù hành vi đã được ghi nhận gián tiếp trong `marker-checks.txt`. Xem Open design point 4–5 về request benign tối thiểu."
      # p_plugin_active: observable=false và KHÔNG trong path (đo được là không phải điều kiện)
      # p_php_filter_wrapper: observable=false → không có probe; xem Open design point 6
      # p_sink_unsanitised_include: B (version-determined) → không probe, không nằm trong paths (G1)
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E2, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "CVE thêm sau V1/V2 (D-035, 2026-10-17); không được dùng để phát triển rule hay signal. Không suy ra held-out một cách tự động (spec §5)."
```

---

## Legend — `control_state_ids` dùng trong draft (để review đối chiếu capture)

| control_state_id | State (lab, 2026-10-17) | Nguồn capture |
|---|---|---|
| `jl427_default` | Joomla! CMS **4.2.7**, cấu hình mặc định (17 webservices plugin bật), container `topup-jl427` → loopback `127.0.0.1:8920` | `cases/CVE-2023-23752/artifacts/427/` |
| `jl428_default` | Joomla! CMS **4.2.8**, cùng cấu hình/DB, container `topup-jl428` → `127.0.0.1:8921` | `cases/CVE-2023-23752/artifacts/428/` |
| `bb137_active` | WP 6.7.1 + Backup Migration **1.3.7 active**, `topup-wp` → `127.0.0.1:8930` (PoC chạy qua tunnel `18930`) | `cases/CVE-2023-6553/artifacts/{a-,a2-,run-a-}*` |
| `bb137_inactive` | WP 6.7.1 + Backup Migration **1.3.7 inactive**, files present | `cases/CVE-2023-6553/artifacts/{b-,run-b-}*`, `marker-checks.txt` |
| `bb138_active` | WP 6.7.1 + Backup Migration **1.3.8 active** (patched control) | `cases/CVE-2023-6553/artifacts/{c-,run-c-,version-observability-138}*` |

## Ghi chú runtime nếu giữ nguyên trạng thái DRAFT (G7)

Với **mọi** probe `pending`, cổng runtime G7 trả `Unknown` cho predicate tương ứng, bất kể response.
Hệ quả nếu researcher **không** nâng probe nào:

- CVE-2023-23752: `p_version_observed` và `p_config_object_readable` đều Unknown ⇒ B và P đều không xác
  định ⇒ **Unknown** cho cả 2 case (4.2.7 và 4.2.8). Đây là hành vi đúng theo thiết kế, **không** phải lỗi.
- CVE-2023-6553: `p_version_observed` Unknown, `p_plugin_files_present` Unknown, `p_php_filter_wrapper`
  không quan sát được ⇒ **Unknown** cho cả 3 case.
- Điều này có nghĩa: chỉ cần nâng 2 probe version + (23752) probe disclosure, 23752 có thể kết luận được;
  6553 **vẫn** có thể kẹt Unknown vì `p_php_filter_wrapper` (Open design point 6) — cần researcher quyết
  trước khi freeze, nếu không thì việc thêm 3 case 6553 sẽ chỉ làm tăng số Unknown.

## Việc **không** làm trong bản draft này

- Không đánh dấu `verified` cho bất kỳ probe nào (kể cả khi capture affected/fixed đã tồn tại).
- Không sửa `notes/collector-mapping-30cve.md`; không tính hash; không đổi `data/public-snapshot/`.
- Không chạy `build_inputs.py`/`harness.py`, không regenerate `experiments/methods/data/`,
  không đụng `experiments/methods/output/benchmark/` hay `benchmark-v2/`.
- Không gửi request, không chạy PoC (lab đã làm ở bước trước; đây chỉ là chép + đọc artifact).
- Không tự quyết các điểm thiết kế dưới đây.

---

## Open design points for the researcher (cần chốt trước khi freeze / D-037)

1. **23752 — một probe version hay hai?** Draft dùng **1 request** tới
   `/administrator/manifests/files/joomla.xml` và ghi `langmetadata.xml` như *quan sát thay thế* trong
   `note`. Có nên cho phép request thứ hai (`language/en-GB/langmetadata.xml`) như fallback chính thức
   (tăng budget lên 3 request/case) hay giữ 1 request và để fallback ngoài contract?
2. **23752 — diễn đạt predicate disclosure để không over-claim.** Vấn đề: "leak config" ngoài thực địa
   không thể chứng minh *giá trị là thật* (canary chỉ có trong lab). Draft yêu cầu `data[]` với các key
   JConfig (`dbprefix`, `sitename`, `host`, `user`) và *ghi nhận thêm* sự có mặt của key bí mật
   (`password`, `secret`) — **không** đòi "giá trị bí mật đúng". Researcher cần chốt: (a) tập key tối thiểu,
   (b) có cần `meta.total-pages` để loại trang giả không, (c) có cấm kết luận Applicable nếu chỉ có key
   names không (D-035 §4 nói rõ: canary-value là tiêu chí **nhãn**, không phải predicate của method —
   xác nhận cách đọc này).
3. **23752 — `p_config_object_readable` có thuộc `paths.all_of` không?** Nó là precondition *mức impact*
   (đặt trong path để biểu diễn được nhánh-b khi endpoint từ chối), nhưng có rủi ro vòng tròn: True của
   nó gần như chính là kết luận. Alternative: coi nó là quan sát impact riêng, không phải điều kiện gate.
   Đây là quyết định ngữ nghĩa, ảnh hưởng trực tiếp nhãn 4.2.8 (nhánh a vs b) và cách fusion hợp nhất.
4. **23752 — có dùng thêm 1 request control (bỏ hẳn param `public`) không?** Capture control đã có
   (401 trên cả 2 build) nhưng draft **không** đưa vào probe list (`?public=false` thì **chưa** đo). Nếu đưa vào, nó loại được khả năng
   "route vốn đã unauth vì lý do khác" — nhưng cũng thêm 1 request và 1 predicate không phân biệt
   affected/fixed. Chốt: giữ làm validation evidence (hiện tại) hay thành probe thứ ba.
5. **6553 — request benign tối thiểu để quan sát reachability.** Draft dùng **POST + `Content-Dir` benign**
   (đúng cái đã đo trên 1.3.8) vì đó là request duy nhất có capture. Các lựa chọn khác **chưa đo**:
   `HEAD` cùng path (có thể 200 mà không chạy thân script), `GET` (có thể 200/0 B hoặc 500 vì guard
   method), hoặc bỏ probe và để reachability `observable: false` (khi đó 6553 không bao giờ kết luận được
   Applicable). Nếu chọn POST benign: cần đo thêm trên **1.3.7 active + 1.3.7 inactive** (hiện chỉ có 1.3.8)
   và quyết định có cần negative control (path PHP không tồn tại) hay không.
6. **6553 — `p_php_filter_wrapper` (observable=false) nằm trong path.** Đây là điểm nặng nhất: giữ nguyên
   thì fusion luôn Unknown cho 6553 (kể cả khi version quan sát được + file reachable), tức 3 case mới
   chỉ tăng Unknown. Hai hướng: (a) giữ là precondition và chấp nhận Unknown (trung thực, nhưng làm loãng
   benchmark); (b) hạ nó thành **giả định môi trường** có ghi nguồn (PHP 8.x mặc định có `iconv`+`filter`;
   capture `X-Powered-By: PHP/8.2.27` + lab chứng minh chain chạy) và **không** đưa vào `paths.all_of`
   — khi đó cần ghi rõ đây là giả định, không phải quan sát. Researcher chốt, không tự chọn.
7. **6553 — một phía (one-sided) reachability.** `false_when` để trống theo G3 ⇒ khi file bị chặn/ẩn, kết
   quả là Unknown chứ không phải nhánh-b. Xác nhận điều này đúng ý (không có nhánh-b nào cho CVE này,
   vì activation không phải điều kiện và "file vắng" không phân biệt được với "direct access bị chặn").
8. **6553 — nguồn advisory là JSON (CVE.org CNA), không phải HTML.** Advisory-only baseline hiện giả định
   đọc advisory dạng trang; với CVE này range phải parse từ `containers.cna.affected[].versions[]`
   (`lessThanOrEqual`). Cần chốt: (a) thêm nhánh parser JSON, hay (b) coi CVE này advisory-only = Unknown
   (spec §4.3 tinh thần: advisory không máy-đọc-được → Unknown), hay (c) dùng CVE.org như `advisory` hợp lệ
   với parser riêng. Lựa chọn này thay đổi kết quả của baseline advisory-only trên 1 case, nên phải chốt
   **trước** khi chạy.
9. **Vị trí + cơ chế freeze.** Hai block này nên (a) merge vào `notes/collector-mapping-30cve.md` thành
   phiên bản 32-CVE rồi freeze hash mới (D-037), hay (b) giữ file riêng `collector-mapping-topup-…` và
   freeze theo cặp hash? Ảnh hưởng loader `build_inputs.py` (đường dẫn file + danh sách CVE) — cần chốt
   cùng lúc với D-037.
10. **Snapshot root thứ hai.** Artifact paths trong draft trỏ `data/public-snapshot-2026-10-17/...`.
    Cần xác nhận harness/loader chấp nhận root thứ hai (hoặc map cohort → root) trước khi regenerate input;
    không tự sửa `experiments/methods/data/`.
