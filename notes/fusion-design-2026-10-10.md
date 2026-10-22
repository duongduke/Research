# Fusion design — bộ rule quyết định (bản nháp)

> Ngày: 10/10/2026. Trạng thái: **KHÓA 2026-10-11 (D-026)** — bộ rule đóng băng trước đánh giá.
> **Amendment R1/R2 (D-027, 11/10/2026):** sửa mâu thuẫn nhánh "thiếu version" (quy tắc canonical
> B/P_i; nhánh config-blocked không cần `B=True`) + thứ tự ưu tiên kiểm bản vá ở Advisory-only.
> (Chưa phải phương pháp đã duyệt.)
> Chỉnh theo review `reviews/Review_fusion_design_2026-10-10.md` (R1–R4) + chốt nguyên tắc 4 điểm
> (D-019). D-011 (protocol) vẫn PROVISIONAL; sửa bản nháp ≠ phê duyệt phương pháp.
> Liên kết: D-016 (4 nguồn + fusion), D-017 (tối ưu fusion: dư thừa + độ quan trọng),
> D-019 (chốt nguyên tắc), D-026 (khóa rule + snapshot 2026-10-11 + metric), D-027 (sửa R1/R2),
> `notes/ground-truth-protocol.md`, `notes/literature-evidence-fusion-2026-10-10.md`.

## 1. Nguyên tắc chung

- Mỗi phương pháp = **đầu vào + luật quyết định** → trả `{Applicable, Not Applicable, Unknown}`.
- Nhãn chuẩn (ground truth) = `{Applicable, Not Applicable}` + `Unresolved` (tách khỏi dự đoán).
- Học từ khảo sát tài liệu: quyết định **theo tầng**, **gom dư thừa**, **precedence khi mâu thuẫn**, trả `Unknown` khi chưa giải được.

## 2. Các loại bằng chứng (sáu loại, không phải sáu đơn vị nhỏ nhất)

> Đơn vị thực tế là một **khẳng định** về một target/CVE/điều kiện có phạm vi + provenance
> (vd: "phiên bản plugin thuộc nhánh affected", "2FA bật", "build này chứa bản vá").

| # | Loại bằng chứng | Nguồn | Trả lời |
|---|---|---|---|
| E1 | Dải version affected | CPE / NVD / advisory | "version ∈ dải?" (mức 1) |
| E2 | Độ nghiêm trọng / loại lỗi | NVD (CVSS/CWE) | "nặng nhẹ, loại gì?" (ưu tiên) |
| E3 | Tiền điều kiện | advisory | "cần điều kiện gì?" (mức 2) |
| E4 | Bản vá / backport | advisory + distro advisory + version history | "đã vá chưa?" (cần liên kết target↔build) |
| E5 | Phiên bản/build **suy ra từ HTTP** | HTTP fingerprint | "máy đang chạy version gì?" (suy ra, không phải version pin trong image) |
| E6 | Dấu hiệu feature/config | HTTP observation | "máy có bật feature đó không?" |

> Lưu ý dư thừa: **E1 bị lặp** ở CPE/NVD/advisory → khi fusion phải **gộp các khẳng định
> tương đương thành 1 khẳng định có provenance**, không cộng 3 lần. Không mặc định "NVD CPE
> lấy từ advisory" cho mọi bản ghi nếu chưa xác minh provenance; các dải khác nhau vẫn là
> khác biệt cần giải thích, không ép thành một khẳng định đồng thuận.

> Lưu ý E5/E4 (R2): (1) E5 là **suy ra từ HTTP** — version pin trong image / package revision /
> config đọc qua SSH thuộc ground truth, không tự là đầu vào phương pháp. (2) Biết distro đã
> backport (E4) ≠ biết target đang chạy gói đó; header `nginx/1.18.0 (Ubuntu)` chưa xác nhận
> package revision, nên chưa thể mặc định kết luận "đã vá" chỉ từ E4.

## 3. Bốn nguồn đơn (mỗi cái chỉ dùng một tập con — theo D-016)

> Nguyên tắc chung cho cả 4 nguồn đơn: **thiếu dữ liệu ≠ version nằm ngoài dải**. Không có bản
> ghi CVE/CPE, range không parse được, hoặc product matching chưa xác định → `Unknown` (không
> suy thành `Not Applicable`).

### 3.1 CPE-only
- **Đầu vào:** E1 (chỉ CPE) + E5 (version).
- **Luật:**
  1. không biết version → `Unknown`
  2. version ∈ dải CPE → `Applicable`
  3. version ∉ dải → `Not Applicable`
- **Điểm yếu:** chỉ mức 1; không thấy backport (E4); không thấy tiền điều kiện (E3); CPE có thể sai/thiếu.

### 3.2 NVD-only
- **Đầu vào:** E1 (CPE của NVD) + E2 (CVSS/CWE) + E5.
- **Luật:** như CPE-only nhưng dùng CPE lấy từ NVD; E2 chỉ là metadata (dùng báo severity, không đổi kết luận Applicable/Not).
- **Điểm yếu:** gần như trùng CPE-only (cùng dải version) — đây chính là phần "dư thừa" cần ghi nhận khi so sánh (NVD ≈ CPE cho kết luận mức 1). **Nếu input thực tế giống nhau thì dự đoán giống nhau là điều phải báo cáo, không bịa khác biệt** (R1).

### 3.3 Advisory-only
- **Đầu vào:** E1 (dải của advisory) + E3 (tiền điều kiện) + E4 (patch) + E5.
- **Luật (thứ tự ưu tiên — không chuyển thẳng thành chuỗi if/elif mù quáng):**
  1. nối được target với build đã vá (E4, cùng yêu cầu liên kết target–build như fusion, §4) → `Not Applicable` (nhánh a). **Ưu tiên trước các nhánh thiếu-precondition** — bằng chứng build đã vá đáng tin đủ cho kết luận âm.
  2. không biết version / không có bản ghi hoặc range không parse được / product matching chưa xác định → `Unknown` (thiếu dữ liệu ≠ version ∉ dải).
  3. version ∉ dải advisory → `Not Applicable`.
  4. version ∈ dải ∧ advisory nêu tiền điều kiện mà **không kiểm được trên máy thật** → `Unknown` (advisory-only không có E6).
  5. version ∈ dải ∧ không có tiền điều kiện **trong phạm vi đã xác định** → `Applicable`.
- **Điểm yếu:** biết điều kiện (E3) nhưng **mù với hệ thống thật** (thiếu E6) → thường kẹt ở `Unknown` cho mức 2. Advisory không nhắc một tiền điều kiện **chưa có nghĩa CVE vô điều kiện** (R4).

### 3.4 HTTP version-string-only
- **Đầu vào:** E5 (phiên bản/build suy ra từ HTTP) + bảng dải affected tham chiếu chung (E1 tối giản — bất kỳ công cụ khớp version nào cũng cần; khai báo nguồn: dải CPE/NVD dùng như lookup table).
- **Luật (chỉ mức 1):**
  1. không quan sát được version → `Unknown`
  2. version ∈ dải → `Applicable`
  3. version ∉ dải → `Not Applicable`
- **Điểm yếu:** không thấy tiền điều kiện (E3), bản vá/backport (E4), dấu hiệu feature (E6); kẹt `Unknown` khi target ẩn version (pilot: Drupal/Roundcube). Đây là baseline "chỉ nhìn banner".
- **Lưu ý trung thực:** khi version quan sát được, dự đoán của HTTP-only ≈ CPE-only ≈ NVD-only (đều là khớp version mức 1). Sự trùng lặp này phải được báo cáo (R1), không bịa khác biệt.

> Lưu ý: HTTP observation (E5/E6) không tự biết version có affected hay không — cần E1 để diễn
> giải. Vì vậy "HTTP version-string-only" (§3.4) dùng đúng nghĩa hẹp: chỉ nhìn version string +
> bảng dải tham chiếu, không dùng E3/E4/E6. Đây là phương pháp đơn thứ 4 theo D-016 (khôi phục
> lại sau R1).

## 4. Fusion (đề xuất) — quyết định theo tầng

Đầu vào: **đủ** E1–E6.

1. **Tầng 1 — xác định version (E5):** dùng fingerprint; nếu ẩn → thử dấu hiệu thay thế. Không ra → `B` chưa rõ, **không** dừng ngay ở `Unknown` — vẫn xét các điều kiện ở tầng dưới; nếu một nhánh độc lập đủ căn cứ (vd mọi đường bị chặn) thì vẫn kết luận được.
2. **Tầng 2 — xác định dải affected (E1, gom dư thừa):**
   - Gom các khẳng định tương đương (CPE/NVD/advisory) thành **1 khẳng định** về "version ∈ dải?", giữ provenance + snapshot (nguồn nào nói gì).
   - Mâu thuẫn → theo **precedence có phạm vi** (xem §4.2), áp cho **cùng khẳng định + cùng phạm vi**.
3. **Tầng 3 — kiểm bản vá / backport (E4):** chỉ kết luận "đã vá" khi **nối được target với build đã vá** (E5 quan sát được dấu hiệu phân biệt bản vá đã kiểm chứng, hoặc package revision được xác nhận qua quan sát cho phép). Biết distro đã backport ≠ biết target đang chạy gói đó (ca nginx: `nginx/1.18.0 (Ubuntu)` chưa xác nhận revision → chưa kết luận đã vá từ E4). Không dùng package metadata trong lab để làm "fusion thắng"; kết quả `Unknown` ở ca này vẫn có ý nghĩa và phải báo cáo.
4. **Tầng 4 — kiểm tiền điều kiện (E3 × E6):** đối chiếu precondition trong advisory với dấu hiệu feature trên HTTP:
   - Mỗi "đường tác động" cần bộ điều kiện A ∧ B ∧ …; đường bị chặn khi **thiếu ≥1 điều kiện bắt buộc** (khớp nhánh (b) luật nhãn âm).
   - "Không thấy dấu hiệu" **chưa có nghĩa feature tắt** (404/403/timeout có thể do route, quyền, proxy, budget). Chỉ gán `False` khi phép quan sát đã được kiểm chứng là đủ để loại điều kiện trong access model đó (R4).
5. **Kết luận (quy tắc canonical B/P_i — không đếm phiếu):**
   - Đặt `B` = target chứa build/code affected (sau khi xét nhận diện E5, dải E1, bản vá E4). `B ∈ {True, False, Unknown}`.
   - Với mỗi đường tác động i trong phạm vi/access model đã xác định, đặt `P_i` = tất cả điều kiện bắt buộc của đường đó. `P_i ∈ {True, False, Unknown}`:
     - `P_i = True` khi mọi điều kiện bắt buộc đều True;
     - `P_i = False` khi ít nhất một điều kiện bắt buộc là False;
     - còn lại là `Unknown`.
   - **Applicable:** `B = True` ∧ tồn tại đường có `P_i = True`.
   - **Not Applicable (nhánh a):** `B = False` (build không affected / đã vá).
   - **Not Applicable (nhánh b — config-blocked):** target đã nhận diện đúng ∧ phạm vi đường đã xác định đủ ∧ **mọi** đường liên quan có `P_i = False`. Nhánh này **không yêu cầu `B = True`**: nếu mọi đường đều bị chặn thì kết luận âm bền vững với cả `B = True` lẫn `B = False` (thiếu version chỉ làm `B` chưa rõ, không chặn nhánh này).
   - **Unknown:** các trường hợp còn lại (giữ lý do + predicate chưa giải được). Thiếu dữ liệu không parse được / product matching chưa xác định / predicate mâu thuẫn chưa giải được → `Unknown`, **trừ khi** một nhánh độc lập khác đã đủ căn cứ.

   Ví dụ kiểm tra luật (trước triển khai):
   - Ba nguồn lặp cùng dải affected; 2FA chưa biết và là điều kiện cần của đường duy nhất → `Unknown` (không phải Applicable do "3 phiếu").
   - Build affected được nhận diện; mọi điều kiện của một đường đã xác định True → `Applicable`.
   - REST tắt nhưng JSON:API còn bật; một điều kiện khác của đường JSON:API chưa biết → `Unknown`, chưa đủ kết luận âm.
   - Mỗi đường đều có ít nhất một điều kiện bắt buộc được xác định False → `Not Applicable`.
   - HTTP nối được target với build đã vá theo bản ghi phù hợp → `Not Applicable`.
   - Chỉ biết upstream version + distro có bản vá, chưa biết revision của target → chưa kết luận đã vá từ E4 → `Unknown` nếu không có căn cứ khác đủ quyết định.

### 4.1 Xử lý trọng số + độ quan trọng (D-017)
- **Độ quan trọng theo tầng:** E3 (tiền điều kiện) + E6 (quan sát feature) **quyết định** mức 2; E1 chỉ là điều kiện cần; E2 là metadata (không đổi kết luận).
- **Trọng số nguồn = precedence cố định (rule-based), khóa trước đánh giá** (CHỐT D-019):
  - Ưu tiên áp cho **cùng một khẳng định + cùng phạm vi** (sản phẩm/build/nhánh); không mặc định "mọi advisory đều thắng mọi dữ liệu NVD".
  - Nội dung dải affected/precondition: **advisory > NVD > CPE** (vendor là nguồn có thẩm quyền cho precondition + affected range).
  - Bằng chứng **trực tiếp** về trạng thái target (E6 quan sát feature) > suy luận gián tiếp từ dải version.
  - **Không học trọng số ở giai đoạn này.** Với ~30 CVE (nhiều trạng thái của cùng CVE phụ thuộc nhau), học trọng số có nguy cơ overfit. Nếu mở rộng sau: chia dev/eval theo CVE, kiểm soát rò rỉ. Không lấy EPSS (dự báo khai thác ở mức quần thể 30 ngày) làm lý do cho trọng số applicability — khác bản chất câu hỏi của đồ án.

### 4.2 Xử lý mâu thuẫn
- Chỉ áp precedence cho **cùng câu hỏi + cùng phạm vi** (sản phẩm/build/nhánh). Advisory upstream nói version affected và distro advisory nói package backport đã vá **không nhất thiết mâu thuẫn** (khác phạm vi build).
- Một advisory cập nhật, đúng nhánh/build có thể giải thích hoặc thay thế thông tin cũ.
- Hai khẳng định đối lập cùng áp dụng cho target mà không giải được → `Unknown` (không đoán).
- Không dùng công thức độc lập `1−∏(1−p)` (các nguồn có tương quan).

## 5. Ánh xạ sang metric

- `Applicable` đúng = True Positive; `Not Applicable` đúng = True Negative.
- `Unknown` = abstention → tính vào `coverage`/`Unknown rate`, không thưởng.
- `recall(Applicable)` giữ toàn bộ ground-truth Applicable ở mẫu số (kể cả ca trả Unknown).

## 6. Trạng thái các điểm mở (đã chốt nguyên tắc theo D-019)

1. **Trọng số — CHỐT:** precedence cố định rule-based (xem §4.1); không học trọng số ở bản đầu. Khóa luật trước đánh giá cuối, không chỉnh sau khi thấy kết quả benchmark.
2. **Dấu hiệu HTTP từng CVE — việc thực nghiệm khi dựng lab:** lập bảng precondition→dấu hiệu khi dựng từng CVE, kiểm trên các trạng thái đối chứng (affected/fixed, config on/off). Không thấy dấu hiệu ≠ feature tắt; điều kiện chưa quan sát được → giữ Unknown.
3. **Phân bố tình huống — gắn tag, không đặt quota trước:** ≥30 CVE khác nhau, mỗi CVE có các trạng thái triển khai. Gắn nhóm (backport / config tắt / ẩn version / CPE sai) để phân tích theo nhóm; số ca mỗi nhóm chỉ xác định sau khi kiểm khả thi + ghi selection log.
4. **Ngưỡng "đủ bằng chứng" — CHỐT:** dựa vào xác định đủ điều kiện bắt buộc của một đường tác động (xem §4 predicate B/P_i), KHÔNG đếm số nguồn đồng thuận. Ba nguồn cùng nói affected không thay thế được một điều kiện cấu hình còn thiếu.
