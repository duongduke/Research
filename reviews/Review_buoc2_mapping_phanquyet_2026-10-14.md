# Review bước 2 — Phán quyết + sửa mapping 30 CVE (bảng phán quyết)

> Ngày: 14/10/2026. Researcher (DeepSeek V4 Pro). Tiếp nối `Review_san_sang_buoc2_mapping_2026-10-14.md`
> (D-029 PROVISIONAL) và `notes/collector-mapping-30cve.md` (bản điền engineer).
> Phạm vi: rà toàn bộ 30 CVE theo `notes/collector-mapping-spec-2026-10-11.md` (D-028) +
> `notes/fusion-design-2026-10-10.md` (D-019/D-026/D-027) + `notes/ground-truth-protocol.md`.
> **Không** sửa snapshot, registry, selection-log, spec, nhãn chuẩn, D-026. Đây là lượt sửa **logic
> mapping**, không phải phê duyệt phương pháp (D-011 vẫn PROVISIONAL).

## 1. Nguyên nhân gốc (một lỗi cấu trúc, nhiều biểu hiện)

Bản điền đã đưa **version + sink (mã lỗi) + patch/backport** — tức các yếu tố thuộc `B` (build bị ảnh hưởng)
— vào `paths.all_of` (thuộc `P_i`, tiền điều kiện cấu hình). Hệ quả:

1. `paths` chứa `NOT(p_installer_public)`/`NOT(p_build_patched_backport)` → nếu `B=True` + feature=False, nhánh
   này có thể `P_i=True` → sinh **Applicable** (ngược ý nghĩa).
2. `false_when` dùng 403/404 → "không thấy = feature tắt" (vi phạm Unknown khi route/auth/proxy nhập nhằng).
3. Ca XSS tách "injection" và "execution" thành **hai đường thay thế** → injection tự thành một đường hoàn
   chỉnh (vi phạm chuẩn D-015/D-024).
4. Probe version `maps_to` predicate dạng `p_*_version_lt_*` với cutoff viết sẵn → gộp E5 (quan sát) với E1
   (dải), rò dải advisory vào CPE-only (vi phạm R1).

**Sửa gốc:** tách `B` khỏi `P_i`. `paths.all_of` chỉ chứa tiền điều kiện cấu hình/truy cập/fixture (E3/E6).
Version/range/patch/sink thuộc `B`, do luật method tính từ `ranges_by_source` + probe E5.

## 2. Các phán quyết toàn cục (G1–G7) — căn cứ của mọi sửa

- **G1 — Cấu trúc B/P_i.** Mỗi condition thêm `kind:` (`build` | `precondition`).
  - `kind: build` = product, version∈range, patch/backport, và **sink** (mã lỗi). KHÔNG nằm trong `paths`.
    Được xác định bởi luật method qua `ranges_by_source` (E1) + patch (E4) + probe version (E5).
  - `kind: precondition` = config/access/fixture/feature (E3/E6). NẰM trong `paths.all_of`.
  - Căn cứ: fusion-design §4.5 (B/P_i canonical); nhánh-b không cần `B=True`; nhánh-a là `B=False` (tách khỏi nhánh-b).
- **G2 — Probe version = quan sát trung lập E5.** Probe quan sát version `maps_to` condition `p_version_observed`
  (kind: build), `interpret` chỉ quyết **có quan sát được version string hay không** (ghi giá trị V), **không** chứa
  cutoff affected. Việc khớp V với dải là **việc của từng method** theo `ranges_by_source` được phép (CPE-only→`.cpe`,
  NVD-only→CPE của NVD, advisory-only→`.advisory`, HTTP-version-only→bảng dải tham chiếu). Căn cứ: F4 + R1.
- **G3 — Không dùng 403/404 đơn lẻ làm False.** `false_when` chỉ được phép là **tín hiệu vắng mặt dương, cụ thể**
  (vd một error-code đặc trưng đã được kiểm chứng). 403/404 trần, hoặc "không thấy form/login/asset" → chuyển sang
  `ambiguity_when` (Unknown). Căn cứ: spec R3 "HTTP 404/403 đơn lẻ không tự là negative signal"; protocol R1; fusion-design §4 tầng 4.
- **G4 — Không có đường tác động phủ định.** Bỏ `NOT(...)` khỏi `paths`. Config-off = precondition config có giá trị
  False trên đường tác động (duy nhất) → nhánh-b. Patch-absence (nginx 23017) là việc của `B` (E4), không phải tiền điều kiện.
  Căn cứ: F1.
- **G5 — XSS impact = execution, không phải injection.** Với stored XSS (6341, 5631, 37383, 12625), đường tác động
  phải chứa điều kiện **browser thực thi / click** (`p_browser_*`, `p_victim_click`). "Injection sống qua sanitizer" là
  sink thuộc `B` (bước trung gian), KHÔNG phải một đường tác động hoàn chỉnh thay thế. Căn cứ: F3 + D-015 (Ca C) + D-023.3/D-024.
- **G6 — `validation.status` là vết bằng chứng, không phải logic.** Giữ 37 `pending` / 4 `needs_control` (dẫn Unknown ở
  runtime). Không nâng lên verified cho đẹp. Định nghĩa `verified` giữ nguyên (đủ control): probe version/identity cần
  quan sát đúng version ở **cả hai** trạng thái affected+fixed; probe feature/config cần **cả hai** cực on+off.
  Hệ quả: nginx 23017 (một trạng thái) hạ `verified→pending` (không tự miễn đối chứng).
- **G7 — Cổng runtime cho probe chưa kiểm chứng.** `interpret.{true_when,false_when}` chỉ được đánh giá thành True/False
  ở runtime khi `validation.status == verified`; `pending`/`needs_control` → predicate trả Unknown (bất kể response), cho
  tới khi có artifact đối chứng. Ghi vào header mapping + sẽ áp khi cài đặt. Căn cứ: "37 pending dẫn Unknown", D-028 R3.

## 3. Xử lý 14 điểm mở (engineer B1–B14)

| # | Điểm mở | Phán quyết |
|---|---|---|
| B1 | nginx 23017 `verified` một trạng thái | **Hạ xuống `pending`** (G6). Tách E5 (header chuỗi quan sát được) khỏi E4 (không phân biệt được build vá); probe chỉ chứng minh E5, chưa đủ control → pending. |
| B2 | repro-capture trùng hình dạng probe (24917/10692/8942-login/12640/12641/44026/5631/37383) | **Không chấp nhận theo nhóm.** Giữ `pending` trừ khi file chứa đúng request/response *benign* của probe, không bị PoC làm đổi trạng thái. Riêng các "probe" thực chất là **khai thác sink** (24917 referer-bypass, 2745 reflection, 5631/37383 sanitizer-survival, 6341 upload) → chuyển condition sang `kind: build` (observable:false), **bỏ probe** (G1/G5). |
| B3 | đường dẫn artifact 41773 ở gốc case | Chấp nhận ghi đường dẫn thật; thêm ghi chú chuẩn hoá (không di chuyển file ở lượt này — không chạy lab). |
| B4 | cờ signal-development 8942/21661 | **Giữ `true`** (có ghi nhận observability trong selection-log/README: author-role không quan sát được, fixture-asset quan sát được, 500 không phân biệt). Không hạ cờ để phóng đại nhóm eval (D-028 R5). |
| B5 | 6340 probe route một cực | Giữ `pending`; không dùng README §3 thay capture thô. |
| B6 | 5631 mâu thuẫn NVD↔CPE range | Giữ nguyên snapshot; ghi provenance hai phía. Ở tầng rule: cùng phạm vi thì advisory>NVD>CPE (D-019), mâu thuẫn chưa giải → Unknown (không sửa theo GT). Ghi vào `ground_truth_note`. |
| B7 | advisory range `Unknown` (8942/10692/44026/25213/10924) | Giữ `Unknown` cho `.advisory` khi không máy đọc được (đúng spec §4.3); không vay CPE/NVD gọi là advisory-only. |
| B8 | NVD↔CPE dư thừa | Giữ ghi nhận (không bịa khác biệt, R1/D-017). |
| B9 | CPE không product-scoped | Giữ; CPE-only/NVD-only nhận diện product từ E5 rồi lọc CPE theo product. |
| B10 | CPE exact-version (1001000 liệt 4.7.2 vulnerable) | Giữ nguyên snapshot; CPE-only có thể trả dương trên bản GT âm (đó là FP của method, được đo). Không hardcode ngoại lệ. Luật CPE xử lý cả range lẫn exact `==`. |
| B11 | pilot thiếu Precondition table; 7602 thiếu capture | Giữ nguyên nguồn (README pilot + lab-spec). 7602 không có capture → các probe để `pending`. CVE đã drop (35489/24284/27956) không thuộc 30 canonical → không có section (đúng). |
| B12 | E3/E6 thiếu artifact (28121/32243 readme…) | Giữ `pending`; không tạo artifact giả. |
| B13 | không có probe impact-path nào verified | Đúng chủ trương (probe chỉ validate predicate, không validate nhãn). Giữ. |
| B14 | chưa freeze | Sau lượt sửa này → khóa version + hash (mục 6). |

## 4. Xử lý 4 findings của người dùng + 6 điểm hướng xử lý

| Finding/Điểm | Phán quyết (ánh xạ) |
|---|---|
| F1 config-off như đường tác động | **G4**: bỏ `path_config_off` chứa `NOT(...)` ở 12640/12641/13671 và `NOT(p_build_patched_backport)` ở 23017. |
| F2 403/404 → False | **G3**: chuyển sang `ambiguity_when`; `false_when` chỉ giữ tín hiệu vắng mặt cụ thể. |
| F3 5631 injection≠execution | **G5**: gộp về một đường chứa `p_browser_*`; áp cả 6341, 37383 (12625 đã đúng). Giữ nhãn Unresolved (D-024). |
| F4 E5 gộp với range | **G2**: probe version → `p_version_observed` trung lập; khớp dải là việc của method theo nguồn. |
| P1 nginx một trạng thái | G6 (hạ pending) + tách E5/E4. |
| P2 capture trong reproduction | B2 (giữ pending; không chấp nhận cả nhóm). |
| P3 5631 range conflict | B6 (giữ provenance; precedence; Unknown khi chưa giải). |
| P4 advisory range thiếu | B7 (Unknown, không vay nguồn khác). |
| P5 CPE exact + 4.7.2 | B10 (đo FP, không hardcode). |
| P6 development flags | B4 (giữ true nếu có ghi nhận; ghi uncertain nếu thiếu). |

## 5. Danh sách sửa cụ thể theo CVE (đã áp vào `notes/collector-mapping-30cve.md`)

Quy ước cột "chuyển sang build": condition rời khỏi `paths.all_of`, gắn `kind: build`. Cột "bỏ probe": probe thực chất
là khai thác sink → condition chuyển `kind: build` + `observable: false`, xoá probe.

| CVE | Chuyển version/sink sang `kind: build` (khỏi path) | Đường tác động còn lại (preconditions) | Sửa probe version (G2) | Sửa false_when (G3) | Khác |
|---|---|---|---|---|---|
| 2014-3704 | p_core_version_lt_732, p_array_keys_unsanitised | path_login_sqli=[p_login_form_reachable] | observe_xgenerator→p_version_observed (family only) | probe_login_form: bỏ 404/403→ambiguity | — |
| 2015-3440 | p_core_version_lt_421, p_content_column_is_text_64k | path=[p_comments_open_on_post] | observe_wp_generator→p_version_observed | probe_comment_form: giữ (200+không form) | — |
| 2017-1001000 | p_core_version_in_411, p_id_arg_not_integer_checked | path=[p_rest_reachable] | observe_wp_generator→p_version_observed | probe_rest_root: 404→ambiguity | ghi chú CPE liệt 4.7.2 vulnerable |
| 2018-7600 | p_core_version_in_affected_86, p_form_api_render_callback_unsanitised | path=[p_user_register_ajax_wrapper] | observe_xgenerator→p_version_observed | probe_register_ajax: 403/404→ambiguity | — |
| 2018-7602 | p_core_version_lt_759, p_confirm_form_destination_unsanitised | path=[p_authenticated_session] | observe_xgenerator→p_version_observed | probe_login_form: 404/403→ambiguity | — |
| 2019-10692 | p_plugin_version_lt_71118, p_fields_not_sanitised | path=[p_plugin_slug_present, p_markers_route_registered] | observe_plugin_readme→p_version_observed | probe_markers_route: 404→ambiguity | — |
| 2019-6340 | p_core_version_lt_8610, p_link_field_fixture(giữ build) | path_rest=[p_rest_module_on, p_auth_content_creation]; path_jsonapi=[p_jsonapi_route_on, p_auth_content_creation] | (không probe version — pilot) | probe_rest_route: 403/406/404→ambiguity; probe_jsonapi: 404→ambiguity | p_link_field_fixture là fixture precondition→giữ P; đã tách 2 đường |
| 2019-6341 | p_core_version_lt_8613, p_invalid_utf8_filename_accepted | **G5**: path=[p_open_registration_user_picture, p_browser_executes_stored_file] | observe_xgenerator→p_version_observed | probe_register_form: 403→ambiguity | bỏ path primitive; giữ Unresolved |
| 2019-8942 | p_core_version_affected, p_meta_input_unfiltered | path=[p_upload_capable_author, p_image_editor_and_self_fetch] | observe_wp_generator→p_version_observed | probe_login_page: 404/403→ambiguity | — |
| 2020-12625 | p_version_lt_144, p_cdata_unescaped | path=[p_message_view_auth, p_browser_executes] | (không probe version) | probe_login_page: 200/404→ambiguity | đã đúng cấu trúc, chỉ đổi false_when |
| 2020-12640 | p_version_lt_144, p_plugins_option_traversal | **G4**: bỏ path_config_off; path_config_on=[p_installer_public, p_attacker_writes_local_php] | (không probe version) | probe_installer_dir: 404/403→ambiguity; probe_login: →ambiguity | giữ 2 trạng thái trong 1 block |
| 2020-12641 | p_version_lt_144, p_im_convert_path_set | **G4**: bỏ path_config_off; path_config_on=[p_installer_public, p_image_attachment_resize] | — | probe_installer_dir: 404/403→ambiguity; probe_login: →ambiguity | — |
| 2020-13671 | p_core_version_lt_899, p_name_not_munged | **G4**: bỏ path_config_off; path_config_on=[p_unsafe_ext_file_field, p_upload_permission] | observe_xgenerator→p_version_observed | — | — |
| 2020-25213 | p_plugin_version_lt_69, (upload writable giữ P) | path=[p_connector_reachable, p_upload_writable_no_block] | observe_plugin_readme→p_version_observed | probe_connector: 301/404→ambiguity | — |
| 2021-23017 | p_version_string_in_upstream_range, p_build_patched_backport | **G4**: bỏ NOT; path_resolver_offbyone=[] (không có precondition quan sát được) → giữ path rỗng + ghi chú | observe_server_header→p_version_observed; **hạ verified→pending** | — | tách E5/E4; E4 không nối được target↔build |
| 2021-24917 | p_plugin_version_lt_191, p_referer_bypass_leaks_secret | path=[p_plugin_whl_present, p_secret_login_configured] | observe_plugin_readme→p_version_observed | probe_secret_login: 200→ambiguity; **bỏ probe_referer_location** (là sink) | — |
| 2021-29447 | p_core_version_in_5670_570, p_getid3_external_entities | path=[p_php8_runtime, p_author_upload, p_oob_attacker_reachable] | observe_wp_generator→p_version_observed | probe_login_page: 404/403→ambiguity | — |
| 2021-41773 | p_apache_2449, p_diroots_require_all_granted | path=[p_file_outside_docroot] | observe_server_header→p_version_observed | — | ghi chú đường dẫn artifact |
| 2021-42013 | p_apache_version_in_2449_2450, p_double_decode_reaches_file | path=[p_diroots_require_all_granted] | observe_server_header→p_version_observed | — | — |
| 2021-44026 | p_version_lt_1412, p_sort_reaches_session, p_contacts_fixture(giữ P) | path=[p_auth_session, p_contacts_fixture] | (không probe version) | probe_login_page: →ambiguity | p_contacts_fixture là fixture→giữ P |
| 2022-21661 | p_core_version_lt_583, p_query_not_int_cast | path=[p_trigger_plugin_present, p_fixture_route_unauth] | observe_wp_generator→p_version_observed | probe_fixture_route: 400→ambiguity (giữ true_when route tồn tại) | — |
| 2023-2745 | p_core_version_affected, p_wp_lang_unsanitised | path=[p_crafted_mo_present] | observe_wp_generator→p_version_observed | **bỏ probe_wp_lang_reflection** (là sink) | — |
| 2023-28121 | p_plugin_wcpay_version_lt_562, p_platform_checkout_header_trusted | path=[p_woocommerce_active, p_known_admin_id] | observe_plugin_readme→p_version_observed | probe_users_route: 401/403→ambiguity | — |
| 2023-32243 | p_plugin_ea_version_affected, p_reset_key_unvalidated | path=[p_elementor_active, p_eael_nonce_unauth, p_known_username] | observe_plugin_readme→p_version_observed | probe_eael_token: 400→ambiguity; probe_users_route: 401/403→ambiguity | — |
| 2023-3460 | p_plugin_um_version_lt_267, p_metakey_filter_bypassable | path=[p_open_registration_form] | observe_plugin_readme→p_version_observed | probe_um_register_form: 404→ambiguity | — |
| 2023-5631 | p_version_lt_1415_or_155, p_crafted_html_mail | **G5**: path=[p_message_view_auth, p_browser_renders_use_data_uri] | (không probe version) | probe_login_page: →ambiguity; **bỏ observe_message_html** (là sink) | giữ Unresolved; ghi NVD↔CPE conflict |
| 2023-5798 | p_plugin_assistant_version_lt_144, p_proxy_unvalidated | path=[p_editor_role] | (probe âm version giữ — đổi maps_to) | probe_login_page: 404/403→ambiguity | — |
| 2024-10924 | p_plugin_rss_version_affected, p_core_version_671 | path=[p_2fa_enabled, p_skip_onboarding_route] | observe_plugin_asset→p_version_observed; observe_wp_generator→p_version_observed | probe_two_fa_route: 404→ambiguity (giữ true_when 400 rest_missing_callback_param) | — |
| 2024-28000 | p_plugin_lscache_version_affected, p_weak_6char_hash | path=[p_nopriv_async_handler, p_crawler_config_on] | observe_plugin_readme→p_version_observed | probe_async_handler: 400→ambiguity | — |
| 2024-37383 | p_version_lt_157, p_crafted_html_mail | **G5**: path=[p_message_view_auth, p_victim_click] | (không probe version) | probe_login_page: →ambiguity; **bỏ observe_message_html** (là sink) | — |

> `p_*_present` (product/plugin hiện diện) là nhận diện target (thuộc `B`/identity) nhưng đồng thời là điều kiện cần
> để lọc CPE theo product. Được giữ ở `kind: build` (identity) khi chỉ nhận diện product; khi nó đồng thời là
> precondition thực (vd plugin phải active để lỗ hổng hoạt động) thì giữ `kind: precondition` trong path. Cụ thể đã
> thể hiện ở bảng trên (vd `p_trigger_plugin_present`, `p_woocommerce_active`, `p_elementor_active` giữ trong path).

## 6. Freeze (sau khi sửa)

- Sau khi áp toàn bộ sửa trên, tính sha256 của `notes/collector-mapping-30cve.md` và ghi version+hash vào file
  (header) + `DECISIONS.md` (D-030). Snapshot `data/public-snapshot/` và nhãn chuẩn giữ nguyên.

## 7. Chi tiết §5 bị thay thế khi áp dụng (file đã khóa là chuẩn; G1–G7 là thẩm quyền)

- **24917** `p_plugin_whl_present` = `kind: build` (identity), KHÔNG nằm trong path → `path=[p_secret_login_configured]`
  (đọc G1-consistent; bảng §5 ghi nhầm `path=[p_plugin_whl_present, ...]`).
- **41773** `p_diroots_require_all_granted` = `kind: precondition` (config misconfig; advisory "if files outside docroot
  are not protected by require all denied, requests can succeed") → NẰM trong path, đồng nhất với 42013. Bảng §5 ghi nhầm
  "build/sink".
- **2015-3440** `p_content_column_is_text_64k` = `kind: precondition` (schema DB, điều kiện triển khai) → NẰM trong path;
  bảng §5 ghi nhầm "chuyển sang build".
- **Hash cuối (đã khóa, D-030):** `f266673ee3f1b2d6ae14b0ac2357a550d63a4013b4eb7f1e8676509248d7fbd1` (2,363 dòng).
