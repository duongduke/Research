# Phán quyết 3 phát hiện V2 (capture) — 15/10/2026

> Researcher (DeepSeek V4 Pro). Căn cứ: báo cáo lab agent (`experiments/methods/captures-v2/README-2026-10-15.md`)
> + mapping D-030/D-032 + fusion-design. Không đổi tiêu chuẩn Applicable, không đổi nhãn, không nới rule.

## 1. CVE-2017-1001000 — probe request sai dạng permalink → D-033
- Lab để **plain permalinks** → `/wp-json/` rơi về front page `200 text/html` (không `routes`). REST index thật ở `/?rest_route=/` (200 JSON + `routes`, cả hai state).
- Mapping `probe_rest_root` request `/wp-json/` mâu thuẫn ngay với mô tả condition `p_rest_reachable` ("plain permalinks → ?rest_route=").
- **Phán quyết (D-033):** sửa request `GET /wp-json/` → `GET /?rest_route=/`. `?rest_route=` chạy được cả plain lẫn pretty → robust. true_when (200 + body `routes`) giữ nguyên. Capture `/?rest_route=/` của lab đã hợp lệ.

## 2. CVE-2024-10924 — namespace + dạng permalink → D-033; còn "fixed không phân biệt được" là KHÔNG phải lỗi
- Namespace đúng là `reallysimplessl/v1` (đọc source `class-rsssl-two-factor-on-board-api.php`, `self::NAMESPACE`; pilot dùng đúng route), KHÔNG phải `really-simple-security/v1`.
- **Phán quyết (D-033):** sửa request `probe_two_fa_route` → `POST /?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding`, body `{}`.
- **"Fixed 9.1.2 với body rỗng trả 400 giống 2FA-on" là KHÔNG phải vấn đề:** probe này chỉ phân biệt **2FA-on (400) vs 2FA-off (404)**. Việc phân biệt vuln/fixed là việc của **B (version)**, không phải probe. Fixed 9.1.2 vẫn B=False (version ∉ range) → NA-a. Không cần sửa gì thêm.
- Capture của lab (400 trên 2FA-on, 404 trên 2FA-off) đã hợp lệ.

## 3. CVE-2023-3460 — fixture hai state lệch page id → sửa lab (không phải mapping)
- Vuln (2.6.6): trang đăng ký ở `?page_id=6`, form `user_login-7`. Fixed (2.6.7): trang đăng ký ở `?page_id=12`, form `user_login-6` — do fixture lệch (leftover từ build 24917), KHÔNG phải tín hiệu bảo mật.
- `probe_um_register_form` hardcode `page_id=6` → chỉ khớp state vuln. Để cặp đối chứng sạch (chỉ khác version), cần **sửa lab**: dựng lại UM trên instance fixed sao cho trang đăng ký cũng ở post 6 (khớp vuln), rồi capture lại.
- Version (readme Stable tag 2.6.6 vs 2.6.7) đã sạch ở cả hai state.

## Tổng kết
- **D-033 (2 mapping amendments):** (1) `probe_rest_root` request `/?rest_route=/`; (2) `probe_two_fa_route` request `/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding`.
- **Lab fix 3460:** dựng lại UM instance fixed cho khớp page id vuln, capture lại.
- **10924 collector:** cùng response phải phát cả `p_2fa_enabled` + `p_skip_onboarding_route` (sửa code, không đổi mapping).
