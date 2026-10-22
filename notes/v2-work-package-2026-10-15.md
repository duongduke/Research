# Work-package V2 — thu + kiểm chứng bằng chứng (3 ca mở đầu)

> Ngày: 15/10/2026. Researcher (DeepSeek V4 Pro). Trạng thái: **work-package cho lab agent**.
> Nguyên tắc: **giữ nguyên tiêu chuẩn Applicable** (`B=True ∧ ∃ P_i=True`) và rule D-026/D-030/D-032; chỉ bổ sung
> bằng chứng (capture) để nâng `pending`→`verified`. KHÔNG đổi phương pháp, KHÔNG nới tiêu chuẩn thành
> "B=True ∧ không đường nào bị chặn" (người dùng chưa chọn). V1 giữ nguyên; V2 chạy lại cùng bộ phương pháp
> trên bộ quan sát V2, mỗi method theo đúng quyền dùng bằng chứng của nó.
> **Vì đã xem V1, đây là phát triển trên tập đã quan sát → 3 ca này ghi `used_for_signal_development = true`** (không phải held-out sạch).

## Nguyên tắc an toàn (bắt buộc)
- Chỉ **probe lành tính** (GET /wp-json/, POST rỗng dò route, GET readme.txt, GET trang đăng ký). KHÔNG gửi payload khai thác,
  không CGI, không RCE, không ghi file ngoài phép. Mọi port loopback. Reset trạng thái (2FA) về ON sau khi thu.
- Lưu **raw request + response nguyên văn** (status + headers + body) vào file artifact mới, kèm dòng đánh dấu trạng thái.

## Ca 1 — CVE-2017-1001000 (WP 4.7.1 / 4.7.2; batch3 stack, port 8711/8712)
- **Request:** `GET /wp-json/` (không auth, không body).
- **Diễn giải:** `p_rest_reachable` = True ⇔ HTTP 200 **và** body JSON có `routes` (đúng true_when mapping). Status 200 đơn lẻ KHÔNG đủ.
- **Đối chứng:** 8711 (4.7.1) và 8712 (4.7.2) đều phải trả 200 + JSON `routes` (REST là tính năng lõi, không bị version-gate).
- **Dừng:** khi cả hai trạng thái có capture sạch 200 + body JSON `routes`.
- **Kỳ vọng:** B=True (4.7.1) ∧ p_rest_reachable=True → fusion 1001000-vuln = Applicable (TP đầu tiên).

## Ca 2 — CVE-2024-10924 (RSS 9.1.1.1:8081 với 2FA toggle; fixed 9.1.2:8082; pilot stack)
- **Request:** `POST /wp-json/really-simple-security/v1/two_fa/skip_onboarding`, header `Content-Type: application/json`, body `{}` (rỗng — chỉ dò route, không nonce/user_id).
- **Diễn giải (một response → HAI predicate, R4: 2 extraction = 1 request):**
  - `p_2fa_enabled` = True ⇔ 400 `rest_missing_callback_param`; False ⇔ 404 `rest_no_route`.
  - `p_skip_onboarding_route` = cùng tín hiệu (route tồn tại → 400, vắng → 404).
- **Đối chứng:** (a) 2FA ON → 400; (b) 2FA OFF → 404; (c) fixed 9.1.2 → ghi kết quả thực tế (kỳ vọng 500/khác, không đoán trước).
- **Toggle 2FA:** dùng wp-cli (`rsssl_options.login_protection_enabled`) để bật/tắt giữa các capture; **restore ON sau khi xong**.
- **Dừng:** khi có capture 400 (ON) + 404 (OFF) + trạng thái fixed.
- **Kỳ vọng:** B=True (9.1.1.1) ∧ cả hai precondition True → fusion 10924-2fa-on = Applicable.
- **Lưu ý collector:** hiện `build_inputs.py` chỉ phát `p_2fa_enabled` (maps_to); cần sửa để **cùng response phát cả `p_skip_onboarding_route`** (ghi trong work-package này cho engineer, không đổi mapping).

## Ca 3 — CVE-2023-3460 (UM 2.6.6 / 2.6.7; batch2 stack)
- **Request 1:** `GET /wp-content/plugins/ultimate-member/readme.txt` → version qua `Stable tag`.
- **Request 2:** `GET /?page_id=6` (trang đăng ký UM) → body chứa `um-form` + `user_login-7` + `_wpnonce`.
- **Diễn giải:** version = readme Stable tag (< 2.6.7 vs ≥ 2.6.7); `p_open_registration_form` = True ⇔ 200 + các marker trên. **Chỉ form thôi chưa đủ — cần cả version để lập B=True.**
- **Đối chứng:** cả 2.6.6 và 2.6.7.
- **Dừng:** khi readme (Stable tag) + form signal có capture ở cả hai trạng thái.
- **Kỳ vọng:** B=True (2.6.6) ∧ p_open_registration_form=True → fusion 3460-vuln = Applicable.

## Đầu ra + hậu xử lý
1. Lab agent: capture raw → file artifact mới (ghi rõ trạng thái/port), báo cáo giá trị quan sát (status + marker).
2. Engineer: sửa `build_inputs.py` (đọc capture mới; ca 10924 phát cả 2 predicate từ 1 response) → regenerate `observations.json` + hash mới; đánh dấu 3 ca `used_for_signal_development=true`.
3. Chạy lại fixture + `harness.py check`, rồi `harness.py benchmark --run-benchmark` → ghi **V2** riêng (`output/benchmark-v2/`), giữ V1 nguyên trạng. **Giữ toàn bộ kết quả, kể cả ca không thành công** (nếu 2FA toggle/route không tái hiện đúng, ghi lại, không bỏ).
4. Không chỉnh mapping/rule/snapshot/nhãn.
