# Diễn giải kết quả bước 4 (phiên bản 1) — 15/10/2026

> Researcher (DeepSeek V4 Pro). Diễn giải raw result ghi ở `CURRENT_STATE.md` §48 +
> `experiments/methods/output/benchmark/`. Đây là **phiên bản thí nghiệm 1** (baseline), giữ nguyên để
> so sánh với các phiên bản sau. Không chỉnh rule/threshold/nhãn sau khi thấy kết quả.

## 1. Kết quả đo (N = 62 = 64 case − 2 Unresolved; 28 Applicable / 34 Not Applicable)

| method | TP | FP | TN | FN_def | U_A | U_N | precision | recall | F1 | coverage | Unknown |
|---|---|---|---|---|---|---|---|---|---|---|---|
| cpe_only = nvd_only = http_version_only | 9 | 3 | 8 | 0 | 19 | 23 | 0.75 | 0.3214 | 0.45 | 0.3226 | 0.6774 |
| advisory_only | 0 | 0 | 7 | 0 | 28 | 27 | N/A | 0.0 | 0.0 | 0.1129 | 0.8871 |
| fusion | 0 | 0 | 9 | 0 | 28 | 25 | N/A | 0.0 | 0.0 | 0.1452 | 0.8548 |

`duplicate_prediction_vectors = [["cpe_only","http_version_only","nvd_only"]]` — ba baseline level-1 trùng vector.

## 2. Điều quan trọng nhất: fusion recall = 0 (bị baseline đơn nguồn áp đảo)

- **Fusion không bao giờ kết luận Applicable** (TP=0, FP=0, precision N/A, recall 0, F1 0). Đây đúng là cảnh báo
  của protocol: "một phương pháp luôn trả Unknown không có giá trị phát hiện dù không có false positive".
- **Nguyên nhân gốc (đo được, không phải suy đoán):** `Applicable = B=True ∧ ∃ P_i=True`, và **mọi** đường tác động
  không rỗng đều có ít nhất một precondition `observable:false`/`pending` → `P_i=Unknown` (cổng G7). Vậy `P_i` không
  bao giờ True → fusion không bao giờ Applicable. Nhánh-b (config-blocked) cũng không bao giờ bắn trên dữ liệu thật
  (6 case branch-b đều Unknown vì identity/version ẩn hoặc precondition gate pending); 9 TN của fusion đều là nhánh-a.
- **So với baseline, fusion giảm FP từ 3 → 0 nhưng mất cả 9 TP.** Ba FP của baseline (theo case list trong metrics.json):
  (1) Apache cấu hình mặc định (`41773__default_249`, version∈range nhưng config chặn → GT NA-b); (2) plugin tắt 2FA
  (`10924__9_1_1_1_2fa_off` → GT NA-b); (3) WordPress CPE sai (`1001000__fixed` 4.7.2 → GT NA-a). Fusion chuyển (1)(2)
  sang Unknown (P_i không quan sát được), (3) sang Not Applicable (advisory precedence). nginx backport (`23017`) thì
  **Unknown ở mọi phương pháp** (không phải FP — version không quan sát được). Precision của fusion là **N/A** (không
  dự đoán ca dương nào), nên **không** nói "fusion thắng về độ chính xác"; fusion vẫn có 9 kết luận âm đúng, nên cũng
  không phải "luôn Unknown". F1 (0 vs 0.45): fusion bị **áp đảo**, không phải "tốt hơn".

## 3. Vì sao (đối chiếu khung 5 nguyên nhân đã chốt ở lượt trước)

Không phải "trần quan sát" cố định — là tổ hợp:
- **(a)+(b) chiếm phần lớn:** precondition có probe nhưng `pending`/thiếu capture (2FA route, REST on/off, installer,
  readme/asset plugin…). Đây là "chưa thu/kiểm chứng", **không phải đã chứng minh không quan sát được**.
- **(c) giới hạn access model thật:** role/permission không lộ qua HTTP unauth.
- **(e) giả định chưa chứng minh:** "ẩn version" Drupal/Roundcube mới thử vài đường.
- **(d) đã sửa:** findings 1–5 + 2745 + D-032 (đã bỏ đúng 1 TP giả của fusion — sửa phép đo cho đúng).

⇒ recall 0 là kết quả **của phiên bản này + bằng chứng hiện có**, không phải giới hạn bất biến của fusion.

## 4. Kết luận trung thực cho luận văn

1. **Phiên bản 1 KHÔNG chứng minh "fusion tốt hơn baseline".** Trên F1, baseline level-1 (0.45) > fusion (0.0).
   Fusion hiện là bộ phân loại "an toàn nhưng vô dụng" (không sai, nhưng không phát hiện).
2. **Đây là phát hiện âm có giá trị:** tiêu chuẩn Applicable chặt (phải xác nhận MỌI precondition True) là **không thể
   thoả mãn** với bằng chứng HTTP-only hiện có — tức mức-2 applicability không xác nhận được từ HTTP khi precondition
   chưa quan sát được. Điều này đúng bản chất câu hỏi nghiên cứu (R1) và không được tô hồng.
3. **Fusion chỉ có giá trị ở phần nó tránh FP:** trên các ca config-chặn và CPE-sai (mà baseline level-1 đoán sai), fusion
   trung thực hơn (0 FP). Nhưng giảm FP 3→0 phải trả bằng mất cả 9 TP, nên F1 vẫn thấp hơn baseline.

## 5. Đường cải thiện (phiên bản 2 — ghi riêng, giữ kết quả cũ)

- **Thu/kiểm chứng tín hiệu precondition (cùng contract, không đổi rule):** capture lại 2FA route 400/404, REST on/off,
  `/installer/`, asset plugin… → nâng `pending`→`verified` → một số `P_i` thành True → fusion có TP > 0. Đây là hướng
  khả thi nhất trong khuôn khổ rule hiện tại (tác động cục bộ, không đổi phương pháp).
- **(Tuỳ chọn, đổi phương pháp — cần quyết định mới):** nới tiêu chuẩn Applicable (vd "B=True ∧ không đường nào bị chặn"
  thay vì "∃ P_i=True") — đổi ngữ nghĩa mức-2, phải ghi amendment + phiên bản riêng + development use.
- **Không:** ép Unknown→Applicable, loại case khó, hay dùng GT bổ sung input method.

## 6. Trạng thái

Bước 4 phiên bản 1 **đã chạy và ghi raw** (`output/benchmark/`). Hai Unresolved XSS (D-024) vẫn chờ tái hiện thủ công.
Kết quả này là mốc so sánh; bước tiếp theo là thu thêm capture precondition cho phiên bản 2 (hoặc quyết định có nới
tiêu chuẩn Applicable hay không) — chưa tự mở rộng phương pháp trong lượt này.
