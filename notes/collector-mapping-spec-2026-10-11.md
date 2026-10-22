# Collector/mapping spec — phần phương pháp cần khóa (R3, D-027/D-028)

> Ngày: 11/10/2026. Trạng thái: **ĐỀ XUẤT** (schema để điền + khóa; chưa phải phương pháp đã duyệt).
> Sửa theo `reviews/Review_collector_mapping_spec_2026-10-11.md` (R1–R5). Liên kết: D-016, D-026,
> D-027, D-028, `notes/fusion-design-2026-10-10.md`, `notes/ground-truth-protocol.md`.

## 1. Vì sao tách hai phần (R3)

Bảng signal từng CVE gồm **hai phần khác bản chất**:

| Phần | Bản chất | Có phải phương pháp? |
|---|---|---|
| (A) **Tri thức CVE** — dải affected, tiền điều kiện, patch reference | dữ liệu tham chiếu (từ snapshot) | Không — là input |
| (B) **Collector + mapping** — chọn request, access model, budget, cách response → True/False/Unknown | quy tắc đo | **Có — phải khóa** |

Thay probe hay cách diễn giải sau khi xem kết quả có thể đổi dự đoán dù B/P_i không đổi →
**khóa cả (B) trước đánh giá**, lưu version/hash và lịch sử sửa. Phần (A) snapshot theo ngày (D-026).

## 2. Schema (mỗi CVE)

```yaml
CVE-XXXX-YYYYY:
  reference:                          # phần A — tri thức CVE, theo từng nguồn (R1)
    ranges_by_source:
      cpe:      {artifact: "data/public-snapshot/<CVE>/cpe.json",      field: "..."}
      nvd:      {artifact: "data/public-snapshot/<CVE>/nvd.json",      field: "..."}
      advisory: {artifact: "data/public-snapshot/<CVE>/advisory.html", field: "..."}
    conditions:                       # mỗi điều kiện một ID ổn định
      p_php8:   {description: "runtime PHP 8", source_ref: "advisory/nvd"}
      p_2fa_on: {description: "2FA enabled",  source_ref: "advisory"}
    paths:                            # đường tác động = all_of các condition ID (R2)
      - {id: path_rest,    all_of: [p_rest_on, p_auth], scope_ref: "..."}
      - {id: path_jsonapi, all_of: [p_jsonapi_on, p_auth], scope_ref: "..."}
  method:                             # phần B — quy tắc đo (khóa)
    contract:                         # R4 — contract request/auth/budget toàn case
      access_model: unauth
      max_requests_per_case: 20       # tổng network request THẬT (kể redirect/retry/auth)
      redirect_policy: "follow"
      retry_policy: "no retry (trừ timeout mạng, đếm thêm)"
      timeout_seconds: 10
    probes:
      - id: observe_php8
        request: {method: GET, path: "/", headers: [...]}
        maps_to: p_php8               # E5 hoặc một predicate condition
        interpret:                    # R3 — điều kiện cụ thể, không prose tự do
          true_when: "X-Powered-By chứa 'PHP/8.'"
          false_when: "X-Powered-By hiện diện và không phải PHP/8., đã loại trừ proxy/strip"
          ambiguity_when: "header thiếu / bị strip / cache không rõ"
          otherwise: Unknown
        validation:                   # R3 — vết kiểm chứng
          status: pending             # pending | verified | needs_control
          control_state_ids: ["wp570_php803", "wp571_php806"]
          artifact_refs: ["experiments/26cve/CVE-2021-29447/artifacts/http-verification.txt"]
    decision_inputs: [E1_cpe, E1_nvd, E3, E5, E6]   # những mảnh bằng chứng method này được đọc (R1)
  development_use:                    # R5 — ghi theo CVE/case
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "..."
```

## 3. Quy tắc chung khi điền (bắt buộc)

- **(R1) Reference theo nguồn:** collector chỉ trả **quan sát** (component/product, version string
  hoặc tập ứng viên, kèm request/response provenance = E5); việc khớp version với range thuộc **từng
  phương pháp**, dùng `ranges_by_source` được phép cho phương pháp đó (CPE-only → `.cpe`, advisory-only
  → `.advisory`, HTTP-version-only → bảng range tham chiếu chung). Không tự sinh một E1=True dùng chung
  cho mọi baseline; CPE và NVD cùng nội dung vẫn giữ nguồn gốc riêng (không bịa khác biệt). E6 không lọt
  vào Advisory-only/CPE-only.
- **(R2) Đường tác động:** biểu diễn bằng `paths` (mỗi đường = `all_of` các condition ID + scope
  version/access model), không phải danh sách precondition phẳng. REST và JSON:API là **hai đường thay
  thế**, không AND thành một điều kiện. Điều kiện không quan sát được dưới access model/budget hiện tại →
  ghi `observable: false`, **không** tạo probe giả.
- **(R3) Đối chứng xác nhận TRẠNG THÁI predicate, không phải nhãn CVE:** vd `p_php8` phải True trên **cả**
  bản lỗi lẫn bản vá (5.7.0/PHP8.0.3 và 5.7.1/PHP8.0.6 đều PHP 8); bản fixed không biến feature thành False.
  Tách **mapping chưa kiểm chứng** (validation.status=pending) khỏi **runtime response không đủ căn cứ**
  (→ Unknown) — hai lý do Unknown khác nhau. **Chưa có artifact của đúng request HTTP quan sát + access
  model + trạng thái đối chứng → để `pending`/`needs_control`, KHÔNG dùng log PoC hoặc metadata nội bộ thay
  thế.** HTTP 404/403 đơn lẻ không tự là negative signal.
- **(R4) Budget = network request thật:** tổng gồm redirect/retry/auth; **hai extraction trên cùng một
  response = 1 request** (không đếm 2). GET/HEAD không tự login (webapp cần POST); authenticated observation
  phải ghi rõ account/role + cách chuẩn bị session + ngân sách. Nếu session được cấp sẵn **ngoài collector**
  (không tạo từ PoC/ground truth) thì nói rõ. Riêng dấu hiệu route `two_fa` 400/404: ghi exact URL + HTTP
  method + body predicate/error code; **không mặc định response POST reproduction giống GET/HEAD**, không
  chuyển sang payload/auth-bypass để có tín hiệu dương.

## 4. Operational notes từ snapshot (2026-10-11)

1. **CPE không product-scoped** (CVE-2021-23017: 25 entry; CVE-2022-21661: 27) → CPE-only/NVD-only phải
   nhận diện product từ HTTP (E5) rồi lọc CPE theo đúng product trước khi so version.
2. **CPE exact-version** (CVE-2017-1001000, CVE-2021-41773 không dạng range) → luật CPE xử lý cả
   `versionStart/End` lẫn exact `==`.
3. **Advisory không machine-readable** → Advisory-only **phải** trích/normalize range từ chính advisory (thủ
   công/script); nếu advisory thiếu range → giữ `Unknown` cho advisory-only. Fusion vẫn được dùng CPE/NVD
   theo quyền nguồn đã khai báo (R1).
4. **2 advisory bot-chặn** (CVE-2020-25213 → 403, CVE-2024-10924 → 202) → dùng fallback vendor (đã lưu).
5. **Redundancy xác nhận (D-017):** cùng 1 advisory URL phục vụ nhiều CVE → đúng lý do khử dư thừa E1.
6. **NVD time-varying:** không re-fetch; dùng bytes + hash đã đóng băng.

## 5. Đơn vị đếm + development use (R5)

- Đây là **30 CVE IDs**, không phải 30 case: version/config/access model tạo **nhiều case** mỗi CVE. Báo
  số **case** resolved/unresolved riêng; Unresolved không đóng góp precision/recall/F1 nhưng giữ capture/dự
  đoán (nếu có) và báo riêng.
- Ghi **per-CVE/per-case** `development_use` (`used_for_rule_development`, `used_for_signal_development`,
  `reason_ref`). Bốn CVE pilot là điểm khởi đầu; **các CVE/case khác dùng để chọn/tinh chỉnh tín hiệu cũng
  phải ghi** — không tự coi cả họ WordPress/Roundcube là development. Chỉ thấy một header trong reproduction
  không tự nghĩa là đã dùng CVE đó chỉnh phương pháp.
- Báo kết quả toàn benchmark và theo nhóm có development use; chỉ gọi nhóm khác là held-out nếu có căn cứ
  tách biệt. Không cần tạo quota CVE mới.

## 6. Trạng thái

Schema đã bổ sung R1–R5; bước kế tiếp: **điền từng CVE** (source refs + probes + control artifacts) rồi
**khóa** collector/mapping thực tế (version + hash). Việc điền giao engineer sau khi snapshot xong (đã xong).
