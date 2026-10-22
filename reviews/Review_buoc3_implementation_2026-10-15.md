# Review bước 3 (implementation) — 5 lỗi triển khai + đánh giá recall (2026-10-15)

> Researcher (DeepSeek V4 Pro). Phạm vi: rà `experiments/methods/` (build_inputs.py, methods.py,
> versioncmp.py, metrics.py, harness.py) theo spec `notes/method-implementation-spec-2026-10-15.md`,
> fusion-design §3–§4 (D-026), mapping D-030, protocol metric. Không sửa snapshot/mapping/nhãn trong
> lượt này; các lỗi sửa = code/input dẫn xuất (tái tạo từ artifact + ghi hash mới). Đề xuất đổi mapping
> ghi riêng ở mục 3 (D-032), KHÔNG âm thầm sửa.

## 1. Xác minh 5 lỗi (từng lỗi: trạng thái, căn cứ, ảnh hưởng, cách sửa)

| # | Lỗi | Xác minh | Ảnh hưởng | Sửa |
|---|---|---|---|---|
| 1 | **REST gán True thiếu bằng chứng** — `build_inputs.py:735` `kind=="status200"` → `predicate = (status=="200")`, trong khi `probe_rest_root` true_when = "HTTP 200 **và body JSON có 'routes'"`. Capture chỉ có "GET /wp-json/ -> 200" (status), không body. | **ĐÚNG.** Regex `GET /wp-json/ -> (\d+)` chỉ bắt status; body 'routes' không có trong artifact. | **Có ảnh hưởng benchmark**: 1001000 vuln → `p_rest_reachable=True` giả → P_i=True → fusion kết luận Applicable (recall tăng 1 bằng bằng chứng giả). Đúng ra phải Unknown. | build_inputs: `status200` → `predicate=None` (Unknown), lý do "body 'routes' thiếu". Đề xuất D-032 hạ probe `verified→pending` (xem mục 3). |
| 2 | **Thiếu range → Not Applicable** — `methods.py:466-467` gọi `match_ranges(version, nvd["ranges"])`/`cpe["ranges"]` không kiểm rỗng; `versioncmp.match_ranges(v, [])` trả `False` (vòng lặp rỗng → không True/Unknown → False). Khi product-filter xoá hết entry → range `[]` → verdict False → `B=False` → NA. | **ĐÚNG.** `_level1` đã xử lý đúng (line 321-322 trả Unknown khi `not src["ranges"]`), nhưng `fusion` KHÔNG. | **Tiềm ẩn** (chỉ bùng khi product-filter ra rỗng). Sai bản chất: thiếu dữ liệu ≠ ngoài range. | fusion: rỗng → verdict `None` (Unknown) kèm lý do "missing data, not out-of-range". |
| 3 | **E4 chưa độc lập** — `methods.py:491` `if B is True:` bọc patch-linkage. E4 chỉ chạy khi đã biết version∈range; không thể lập `B=False` khi version ẩn/range chưa rõ (trái §3.3 rule (1) + §4 tier 3: E4 ưu tiên, lập NA-a độc lập version). `advisory_only` đã đúng (E4 first, line 375-381); `fusion` chưa. | **ĐÚNG.** | **Tiềm ẩn** (hiện không có probe patch-linkage nào `verified` nên không bùng). | fusion: chuyển E4 lên trước tier version/range; nếu linked → B=False (NA-a); else mới xét version/range. |
| 4a | **WooPayments advisory gom 1 khoảng** — `build_inputs.py:928` `[{"start_including":"4.8.0","end_excluding":"5.6.2"}]`, trong khi advisory liệt kê bản vá theo nhánh (4.8.2/4.9.1/5.0.4/5.1.3/5.2.2/5.3.1/5.4.1/5.5.2/5.6.2). Khoảng đơn `4.8.0≤v<5.6.2` sẽ coi 5.5.2 là vulnerable (sai). | **ĐÚNG.** | **Tiềm ẩn** (case 5.6.1/5.6.2 vẫn đúng với khoảng đơn; sai với phiên bản nhánh giữa). | build_inputs: mã hoá union theo nhánh (mỗi nhánh `[branch_first, patch)`) từ chính danh sách patch của advisory. |
| 4b | **2745 ngưỡng 4.1.38 vay từ CPE/NVD** — `build_inputs.py:923` `{"op":"lt","version":"4.1.38"}`. Advisory chỉ nói "All versions since WordPress 4.1 have also been updated" (không có số 4.1.38; số này từ CPE/NVD). | **ĐÚNG.** Vi phạm source isolation (advisory-only không được vay CPE/NVD). | **Tiềm ẩn** (case 6.2.0/6.2.1 không phụ thuộc 4.1.38). | build_inputs: bỏ `4.1.38`; giữ `[{line:"6.2", end_excluding:"6.2.1"}]` + scope_note "các dòng cũ chỉ có câu 'since 4.1 updated', không có fixed version cụ thể → Unknown". |
| 5 | **check đã tính metric** — `harness.py:327,338` gọi `evaluate()` (→ `metrics_mod.evaluate()`) trên case thật, dù docstring nói "no accuracy number is computed". | **ĐÚNG.** `evaluate()` tính confusion+precision/recall/F1 in-memory (không ghi file, không inspect, nhưng có tính). | **Quy trình** (không ảnh hưởng dữ liệu; ghi nhận đúng hành vi trước đây, không viết lại thành "chưa từng tính"). | harness: `mode_check` dùng `build_context`+`predict_all` (chỉ dự đoán, không metric); label-isolation so sánh `predict_all` dưới swap. |

**Kết luận xác minh:** 1 lỗi ảnh hưởng benchmark hiện tại (finding 1: recall fusion bị thổi +1 bằng bằng chứng giả), 4 lỗi tiềm ẩn/đúng-bản-chất nhưng chưa bùng (2, 3, 4a, 4b) + 1 lỗi quy trình (5). Không lỗi nào đổi nhãn chuẩn hay snapshot.

## 2. Đánh giá lại recall thấp của fusion (tách nguyên nhân, không gộp)

Phân loại các ca Applicable mà fusion trả Unknown (theo 5 nguyên nhân người dùng nêu):

| Nguyên nhân | Ví dụ cụ thể | Bản chất | Có thể cải thiện? |
|---|---|---|---|
| (a) Thiếu capture trong artifact hiện có | 2FA route 400/404 đã QUAN SÁT ở pilot (§23 finding 2) nhưng không capture sạch → pending | bằng chứng **đã tồn tại ngoài artifact**, chỉ chưa được thu lại đúng contract | **CÓ** — thu lại capture (lab, không đổi rule) |
| (b) Probe/predicate chưa kiểm chứng (pending/needs_control) | installer, REST on/off, author-role: probe có nhưng pending | tín hiệu **chưa được kiểm chứng**, không phải đã chứng minh không quan sát được | **CÓ** — validate bằng cặp đối chứng |
| (c) Tiền điều kiện ngoài access model/ngân sách hiện tại | author role (8942/29447/5798), content-creation (6340), authenticated (7602/44026) | giới hạn **access model** (login form không lộ role); chưa xét quan sát authenticated | **CÓ** (một phần) — mở rộng access model (đổi phương pháp, cần quyết định mới) |
| (d) Lỗi triển khai bỏ qua bằng chứng đủ mạnh | finding 1 (REST True giả), finding 2/3 (B sai/Unknown sai) | **lỗi code**, không phải giới hạn quan sát | **CÓ** — sửa ngay (lượt này) |
| (e) Giới hạn chỉ đang **giả định**, chưa chứng minh | "Roundcube ẩn version" (chỉ thử /CHANGELOG 403), "Drupal chỉ lộ family" (chưa thử CHANGELOG/asset version-specific) | **giả định chưa được chứng minh** là không quan sát được | **CHƯA RÕ** — cần khảo sát thêm tín hiệu version trước khi kết luận "trần" |

**Sửa lại khung nhận định:** phát biểu trước đây "trần quan sát HTTP, không phải lỗi code" là **gộp quá mức**. Đúng hơn:
- Một phần recall thấp là **giới hạn thật** (c): role/permission không lộ qua HTTP unauth.
- Một phần là **chưa thu/kiểm chứng** (a)+(b): tín hiệu đã/đáng lẽ quan sát được nhưng capture thiếu hoặc probe pending.
- Một phần là **giả định chưa chứng minh** (e): "ẩn version" của Roundcube/Drupal mới chỉ thử một vài đường, chưa loại trừ.
- Một phần là **lỗi code** (d): đang sửa lượt này.

**Hệ quả cho luận văn:** không được kết luận trước "fusion thắng precision/thua coverage" khi chưa chạy benchmark, và không được gọi recall thấp là "trần quan sát" khi phần lớn nguyên nhân là (a)+(b)+(e) (chưa thu bằng chứng, chưa kiểm chứng, chưa chứng minh). Các baseline cũng chịu cùng giới hạn E5/G7 (version ẩn → baseline cũng Unknown), nên không mặc định baseline đoán được.

**Cải thiện recall (phân biệt 3 mức):**
1. **Sửa lỗi** để implementation đúng rule hiện tại (lượt này): findings 1–5.
2. **Thu/kiểm chứng thêm tín hiệu theo contract hiện tại**: capture lại 2FA route, installer, REST on/off, author-role (nếu có tín hiệu) → nâng pending→verified. KHÔNG đổi rule, chỉ bổ sung bằng chứng.
3. **Mở rộng access model / thêm probe / đổi rule**: đây là **thay đổi phương pháp** → quyết định mới + phiên bản thí nghiệm riêng + ghi development use.

Không ép Unknown→Applicable, không loại case khó, không dùng GT bổ sung input method. Giữ metric đã chốt (recall/F1 giữ U_A).

## 3. Đề xuất D-032 (mapping amendment, KHÔNG âm thầm sửa)

- **Nội dung:** hạ `CVE-2017-1001000.probe_rest_root.validation.status` từ `verified` → `pending`.
  Căn cứ: true_when = "HTTP 200 và body JSON có 'routes'", nhưng artifact chỉ ghi status 200 (không body). Theo
  định nghĩa D-030 "verified = artifact khớp true_when/false_when", body 'routes' chưa được khớp → chưa đủ verified.
  (Đây là lỗi thừa kế từ bước 1/2; lượt này chỉ ghi nhận, chờ chấp thuận rồi áp + ghi hash mới.)
- **Ảnh hưởng nếu áp:** hash mapping đổi (D-030 → D-032). 1001000 `p_rest_reachable` → Unknown ở runtime (đúng).

## 4. Kế hoạch sửa (giao engineer) + đối chứng

- Sửa code: build_inputs.py (status200→None; 28121 union nhánh; 2745 bỏ 4.1.38) → tái tạo observations.json/advisory_ranges.json + hash mới; methods.py (fusion empty-range→None; fusion E4 độc lập); harness.py (mode_check không gọi evaluate).
- Bổ sung fixture: (i) status200 thiếu body → Unknown; (ii) CPE/NVD range rỗng → Unknown (không NA); (iii) **E4 cặp đối chứng**: cùng input, có patch-linkage → NA-a, bỏ patch-linkage → Unknown (chứng minh E4 hoạt động, không phải nhờ range rỗng); (iv) advisory union nhánh: version ở nhánh đã patch → out-of-range.
- Chạy lại fixture (phải pass) + `harness.py check` (chỉ cấu trúc, không metric).
- Chưa chạy benchmark (bước 4).
