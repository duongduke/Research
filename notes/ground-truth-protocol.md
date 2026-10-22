# Ground-truth protocol (đề xuất cho câu 4 — nguồn nhãn "Applicable")

> Ngày: 06/10/2026. Trạng thái: **ĐỀ XUẤT** (researcher soạn; chưa trình trợ giảng, phải
> phản biện được khi trình). Liên kết: `DECISIONS.md` D-011 (PROVISIONAL), D-012, D-013
> (PROVISIONAL — các bản sửa từ 2 lượt review 06/10).
>
> **Revision log:**
> - Lượt 1 (R1–R4, `reviews/Review_de_xuat_notes_2026-10-06.md`): (R1) nguồn quan sát tiền
>   điều kiện của phương pháp (HTTP) tách khỏi cấu hình ground truth; (R2) tách Unknown nhãn
>   chuẩn khỏi Unknown dự đoán; (R3) nhãn âm có căn cứ chặt; (R4) đếm CVE khác case.
> - Lượt 2 (D-013, `reviews/Review_protocol_va_pilot_sau_sua_2026-10-06.md`): sửa logic nhãn
>   âm (hai nhánh; mỗi đường thiếu ≥1 điều kiện bắt buộc, không cần mọi điều kiện vắng);
>   Unresolved không phải lớp mục tiêu; Unknown = từ chối trung thực, đo cost-of-miss + coverage.
> - Lượt 3 (D-015, từ kết quả pilot 07/10/2026): "reproduce thành công" = hiệu ứng quan sát
>   được ngoài băng tần, KHÔNG dựa trên mã HTTP (5xx có thể đi kèm khai thác thành công).
> - Lượt 4 (D-025, `reviews/Review_dinh_nghia_nhan_va_prediction_2026-10-11.md`): (R1) nhánh âm
>   (a) nói về **build** (đã vá), không chỉ version ngoài dải — backport giữ version trong dải;
>   (R2) "thành công" = kiểm chứng tác động thực sự của CVE, không suy từ mã HTTP (nội dung file
>   qua HTTP vẫn là bằng chứng trực tiếp nếu đối chiếu đủ marker/fixture/logs); (R3) reproduction
>   mô phỏng phải ghi rõ bước mô phỏng + quyền giả định + phạm vi chứng minh; (R4) "mọi đường" =
>   mọi đường trong phạm vi CVE/version/config/actor đã xác định; Unknown = từ chối kết luận,
>   không phải kết luận sai chắc chắn (vẫn giảm coverage, bỏ lỡ ca dương). (R5) nhãn âm đã-vá
>   (nhánh a) dùng bằng chứng danh tính build + đối chứng bản vá, không cần khai thác dương.
> D-011 vẫn PROVISIONAL; **sửa bản nháp ≠ phê duyệt phương pháp**.

## Mục đích

Quy định cách gán nhãn chuẩn cho benchmark **độc lập với phương pháp được đánh giá**
(fusion), để không circular (D-003).

## Đơn vị đánh giá (case)

Mỗi case = bộ tứ **(product, version/build, configuration, CVE)**. Ở mức 2, `configuration`
là một phần định danh case (cùng version khác config → khác case). Một CVE có thể sinh
nhiều case (xem mục "Đếm CVE vs case").

## Tập nhãn — hai lớp riêng biệt

- **Nhãn chuẩn (ground truth):** `{Applicable, Not Applicable}` + một bucket **`Unresolved`**
  cho ca mà người gán nhãn chưa xác định được trạng thái thật (reproduction/config chưa kết
  luận được). **Không dùng "Unknown" làm nhãn chuẩn.**
- **Đầu ra phương pháp (dự đoán):** `{Applicable, Not Applicable, Unknown}` (giữ theo D-007).

`Unresolved` **không phải lớp mục tiêu** — nó chỉ là trạng thái "chưa gán được nhãn". Không
chủ động chọn ca không chấm được chỉ để đủ lớp; ca Unresolved phải được lưu + báo lý do.

## Ranh giới thông tin (R1) — phương pháp được thấy gì

Phương pháp (fusion) và baseline chỉ được nhận **hai loại thông tin**:

1. **Tri thức chung về CVE** — dữ liệu công khai: CPE/NVD, vendor advisory, version
   history, patch reference. Cho biết *lỗi cần điều kiện gì*.
2. **Bằng chứng quan sát được của mục tiêu cụ thể qua HTTP** — product/version
   (fingerprint) và các **dấu hiệu tiền điều kiện** thu được trong ngân sách quan sát.

**Cấu hình nội bộ lab** (module nào bật, quyền gì, DB/account state) **chỉ dùng để chấm
ground truth**, không bao giờ là đầu vào của phương pháp. "Configuration là phần định danh
case" ≠ scanner được đọc trực tiếp trường configuration.

Mỗi CVE phải có **bảng tiền điều kiện** (do người dựng lab soạn):

| Tiền điều kiện | Dấu hiệu HTTP dự kiến | Cách thu (ngân sách) | Chỉ dành ground truth |
|---|---|---|---|
| … | … | … | … |

- Phân biệt **unauthenticated** vs **authenticated**; không suy "không thấy endpoint" =
  "tính năng tắt" (thiếu bằng chứng ≠ vắng mặt).
- Dấu hiệu chưa đánh giá được độ đặc hiệu chỉ là **dấu hiệu**, không mặc định là bằng
  chứng chắc chắn.

## Nguồn ground truth (2 lớp, tách bạch theo D-003)

1. **Lớp A — dải affected (mức 1):** vendor advisory + patch reference (NVD/CPE). Nguồn
   công khai. Chỉ dùng để xác định dải affected; **không tự đủ** để đóng nhãn âm (xem luật nhãn).
2. **Lớp B — applicability (mức 2):** **reproduce trong sandbox** — dựng đúng (product,
   version, config), chạy tiền điều kiện + PoC có kiểm soát, ghi kết quả.

`source/binary evidence` → tùy chọn (không bắt buộc để gán nhãn).

## Luật quyết định nhãn chuẩn (R3 — nhãn âm có hai nhánh)

Nhãn âm có **hai nhánh độc lập**, chỉ cần một nhánh thỏa là đủ:

**(a) Build đã xác minh không bị ảnh hưởng hoặc đã chứa bản vá** — danh tính build + dải
affected **đáng tin** (đã xác minh build/package identity, advisory, patch). Version nằm ngoài
dải là **một** cách xác lập nhánh này, **không phải điều kiện bắt buộc cho mọi bản vá**:
backport có thể giữ upstream version trong dải affected mà build vẫn đã vá (vd nginx
CVE-2021-23017). Nhánh này **không cần** thêm điều kiện cấu hình tắt.

**(b) Bản bị ảnh hưởng nhưng mọi đường tác động bị loại trừ** — với mỗi **đường tác động
liên quan** (một chuỗi tiền điều kiện cần thiết A ∧ B ∧ …), đường đó bị chặn khi **thiếu ít
nhất một điều kiện bắt buộc** (thiếu A là đủ chặn đường đó). **Không cần mọi điều kiện đều
vắng.** Nếu có nhiều đường (đường thay thế), phải kiểm từng đường.

**"Mọi đường" luôn là mọi đường liên quan trong phạm vi CVE, phiên bản, cấu hình và
actor/access model đã xác định** — **không** phải khẳng định "không tồn tại bất kỳ cách tấn
công nào". Khi phạm vi đường chưa đủ hoặc một điều kiện chưa xác minh, **không** đóng nhãn âm
từ sự im lặng của phép quan sát.

Ví dụ: tắt REST core chưa đủ để đóng Not Applicable nếu JSON:API — một đường khác — vẫn còn
đủ điều kiện; LiteSpeed CVE-2024-28000: hash vẫn có thể sinh khi crawler tắt → đường đó chưa
bị chặn. Thiếu installer của Roundcube chặn được đường *qua installer*, nhưng **chưa** tự chứng
minh mọi actor có quyền sửa config/filesystem đều bị chặn.

| # | Điều kiện | Nhãn chuẩn |
|---|---|---|
| 1 | (nhánh a) danh tính build + dải đáng tin ∧ build không bị ảnh hưởng / đã chứa bản vá | **Not Applicable** |
| 2 | build thuộc phạm vi ảnh hưởng (case/version/config/access model đã xác định) ∧ reproduce chứng minh tác động của đúng CVE | **Applicable** |
| 3 | (nhánh b) version ∈ dải ∧ mỗi đường tác động liên quan thiếu ≥1 điều kiện bắt buộc (đã kiểm từng đường bằng cặp đối chứng) | **Not Applicable** |
| 4 | version ∈ dải ∧ reproduce thất bại ∧ tiền điều kiện không xác định / phép thử chưa tin cậy | **Unresolved** (không gán) |
| 5 | không xác định được version / dải đáng tin | **Unresolved** (không gán) |

Ca rơi vào #4–#5 **không phải nhãn Unknown** — chúng là nhãn chuẩn **chưa giải quyết**,
báo cáo riêng, không đưa vào mẫu số tính precision/recall (xem "Hai loại Unknown").

**Đánh giá "reproduce thành công"** = **quan sát và kiểm chứng được tác động thực sự của CVE**,
**không suy từ mã HTTP trả về**. Một khai thác thành công có thể đi kèm mã 5xx (gadget chạy
trong `__destruct` rồi request lỗi); ngược lại 200/403 không tự chứng minh thất bại. Loại bằng
chứng tác động được quy định **theo từng CVE** và phải có artifact + đối chứng: marker kiểm
trong filesystem, browser execution (XSS) hoặc callback/nghe mạng (SSRF/XXE) là các cách phù
hợp tùy loại tác động; **nội dung file thu qua HTTP cũng có thể là bằng chứng trực tiếp** (vd
file disclosure) khi đối chiếu đủ marker/fixture/logs. Không lấy một marker được tạo bằng
**hành động khác** làm bằng chứng cho CVE đang xét.

**Phạm vi reproduction (mô phỏng vs tái tạo đầy đủ):** khi một ca config-gated cần "bật" một
điều kiện hoặc đặt trước fixture (vd khôi phục `/installer/`, đặt sẵn file PHP, giả định quyền
ghi filesystem), tài liệu case phải ghi rõ **bước nào được mô phỏng, quyền nào được giả định,
và phạm vi mà reproduction chứng minh** — không trình bày như một chuỗi tấn công đầy đủ của
attacker chỉ qua HTTP. Ví dụ CVE-2020-12640: control dương đặt sẵn `plugins` chứa traversal +
file PHP → chứng minh tác động của loader trong case có fixture đó, **chưa** chứng minh attacker
HTTP-only tự đi qua installer + ghi config + đặt file.

**Loại bằng chứng theo từng nhánh (R5):** nhãn dương (Applicable) và nhánh-b cần **bằng chứng
thực thi/tác động** (reproduction); nhánh-a (build không affected / đã vá) cần **bằng chứng
danh tính build + đối chứng bản vá**, **không** cần một khai thác dương thành công (vd nginx
CVE-2021-23017: đối chiếu package revision với bản vá, không chạy exploit). "Reproduce" ở đây
nghĩa là tái tạo đúng trạng thái triển khai để chấm nhãn — **không bắt buộc mọi nhãn đều kèm
một khai thác dương**.

**Căn cứ của từng nhãn:** bảng định nghĩa ở trên chỉ là **quy tắc chấm**; mỗi nhãn cụ thể còn
cần **manifest (pin version/digest), bảng tiền điều kiện, đối chứng (affected/fixed, config
on/off) và artifact truy vết** (advisory ref + reproduce/đối-chứng + config diff). Một nhãn
không có căn cứ truy vết này thì chưa thể bảo vệ.

## Hai loại Unknown (R2) + cách đo

- **Nhãn chuẩn Unresolved** = người gán nhãn chưa xác định được trạng thái thật. Báo riêng,
  không phải lớp mục tiêu.
- **Dự đoán Unknown** = phương pháp từ chối kết luận trên ca **đã có nhãn chuẩn**. Đây là
  hành vi **abstention** — có thể là **câu trả lời trung thực** khi thiếu bằng chứng; nhưng nó
  **không phải một kết luận nhị phân sai chắc chắn** — nó vẫn **giảm coverage** và **bỏ lỡ ca
  dương trong recall tổng thể**. Phân biệt rõ với một **kết luận chắc chắn nhưng sai** (false
  positive/negative). Một phương pháp luôn trả Unknown không có giá trị phát hiện dù không có
  false positive. Không thưởng "đoán chắc thiếu căn cứ" chỉ để tăng coverage.

Nếu lab biết triển khai bị ảnh hưởng (Applicable) nhưng scanner thiếu bằng chứng, nhãn chuẩn
vẫn là **Applicable**; phương pháp có thể trả Unknown — đó là **bỏ lỡ positive có đếm được**
(cost-of-miss), không phải ca "không chấm được".

**Metric (chốt theo D-026; công thức rõ theo D-027 — chỉ cho case có nhãn đã xác định; Unresolved báo riêng, ngoài N):**
- `coverage` = số dự đoán {Applicable, Not Applicable} / số ca có nhãn chuẩn đã xác định.
- `Unknown rate` = cùng mẫu số; bằng `1 − coverage` khi mọi ca đều có dự đoán.
- `precision(Applicable)` = trên các dự đoán Applicable.
- `recall(Applicable)` = giữ **toàn bộ** ground-truth Applicable trong mẫu số, **kể cả ca bị
  trả Unknown** (không lặng lẽ bỏ Unknown rồi báo recall cao hơn).
- Nếu báo độ đúng chỉ trên ca phương pháp kết luận, phải ghi rõ là **metric có điều kiện**
  và trình **kèm coverage**; tách rõ **dự đoán sai chắc chắn** khỏi **abstention**.

Bảng confusion + công thức (chỉ ca đã xác định nhãn):

| GT \ dự đoán | Applicable | Not Applicable | Unknown |
|---|---|---|---|
| Applicable | TP | FN_def | U_A |
| Not Applicable | FP | TN | U_N |

- `FN_def` = kết luận âm **sai chắc chắn**; `U_A` = ca dương bị **bỏ lỡ** do abstention. Báo
  hai số riêng, **không** đồng nhất Unknown với kết luận âm.
- `N = TP + FP + TN + FN_def + U_A + U_N`
- `precision = TP / (TP + FP)`
- `recall = TP / (TP + FN_def + U_A)` — Unknown trên ca dương nằm trong mẫu số (cost-of-miss).
- `F1 = 2·TP / (2·TP + FP + FN_def + U_A)` — giữ chi phí bỏ lỡ `U_A`; **không** dùng công thức
  F1 bỏ `U_A` hoặc bỏ Unknown trước khi gọi metric.
- `coverage = (TP + FP + TN + FN_def) / N`
- `Unknown rate = (U_A + U_N) / N`
- Mẫu số 0 → báo `N/A`; `F1 = 0` khi `TP = 0` và mẫu số dương. Không đổi chính sách sau khi
  thấy kết quả.

## Đếm CVE vs case (R4)

Theo dõi 4 con số riêng:
- `n_unique_cves` — số **CVE ID khác nhau** (mục tiêu **≥30** theo D-010).
- `n_deployments` — số triển khai (version × config) đã dựng.
- `n_cases` — số đơn vị đánh giá `(product, version, config, CVE)`.
- `n_observation_conditions` — số điều kiện quan sát riêng biệt được thử.

Biến thể config **không** làm tăng `n_unique_cves`. Ví dụ 30 CVE × 3 config = 30 CVE, 90
case. Các case cùng CVE **phụ thuộc nhau**: không chia ngẫu nhiên config/version cùng CVE
vào cả tập chỉnh luật và tập đánh giá rồi coi là độc lập.

## Chống circularity (độc lập nhãn)

- Người gán nhãn **KHÔNG** xem dự đoán của phương pháp.
- Nhãn = advisory (range) + reproduce (outcome) + config diff; đầu ra fusion **không bao
  giờ** là đầu vào gán nhãn.
- **PoC thất bại không tự sinh nhãn âm** — phải qua phân tích tiền điều kiện (khớp nguyên
  tắc "PoC fail ≠ negative").
- Mỗi nhãn kèm vết truy: advisory ref + artifact reproduce + config diff.

## Vì sao phản biện được

- Reproduce = **bằng chứng thực thi** (execution evidence), lấp đúng khoảng trống Vuln2Action
  (bài đó không có execution validation).
- Traceable (mọi nhãn truy về artifact) và độc lập với phương pháp.
- `Unknown`/`Unresolved` được tôn trọng; thiếu bằng chứng ≠ an toàn.

## Phạm vi

≥30 **CVE ID khác nhau** (ưu tiên CMS/framework + một ít Apache/nginx), mở rộng nếu còn
thời gian.
