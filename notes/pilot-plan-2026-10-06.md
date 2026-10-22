# Pilot plan — kiểm chứng tái tạo + quan sát tiền điều kiện (3 ca)

> Ngày: 06/10/2026. Trạng thái: **ĐỀ XUẤT** (thiết kế, chưa chạy). Revision: bản này đặc tả
> release/control/fixture/reset/budget + access model theo D-013. Các số release là **đề xuất
> để khóa trong bước verify** — chưa tải/kiểm checksum.

## Mục tiêu & ranh giới

Trước khi scale ≥30 CVE, chạy 3 ca đại diện để kiểm (a) tái tạo được không, (b) tiền điều
kiện quan sát được qua HTTP không (R1). **Pilot có ích kể cả khi phát hiện ca không dựng được
hoặc tiền điều kiện không quan sát được** — đó là kết quả về giới hạn phương pháp. Phân biệt
**hoàn thành đánh giá khả thi** với **đủ điều kiện đưa CVE vào benchmark**; ghi thất bại có
nguyên nhân, không chọn lại ca cho đến khi mọi thứ thuận lợi.

## Access model (quy định chung)

Mỗi ca ghi rõ scanner có **tài khoản** (authenticated) hay chỉ **quan sát không đăng nhập**
(unauthenticated). **Không gộp hai model khi kết luận.** Mặc định pilot = **unauthenticated**
để đo giới hạn cứng; nếu cần, thêm biến thể authenticated riêng.

## Ngân sách quan sát (đo được, chốt trước)

- Tối đa **20 request / ca**, chỉ GET/HEAD, danh sách path **chốt trước** (bảng mỗi ca).
- Không probe thêm sau khi đã thấy kết quả (tránh khảo sát tùy ý).
- Không dùng SSH/config để "quan sát" (chỉ ground truth). Không suy 404 = "feature tắt".

## Fixture & reset (chung)

- Mỗi ca: manifest pin (app/plugin + PHP + DB + web server + dependency), ghi checksum/digest.
- DB snapshot trước/sau; reset giữa lần chạy (dừng container ≠ reset volume/inbox/cookie).
- Thu **đầu vào phương pháp trước PoC** hoặc trên bản reset tương đương — không dùng trạng
  thái account/inbox/cookie đã đổi sau PoC.

---

## Ca A — Really Simple Security CVE-2024-10924 (auth bypass, 2FA)

| Mục | Giá trị (khóa khi verify) |
|---|---|
| Bản lỗi | plugin 9.1.1.1 (∈ 9.0.0–9.1.1.1), WordPress (VD 6.7.x) |
| Bản fixed (đối chứng) | plugin 9.1.2 |
| Trạng thái config | (i) 2FA **bật**; (ii) 2FA **tắt** (đối chứng nhánh b) |
| Access model scanner | unauthenticated |
| Fixture | 1 tài khoản admin đã biết; toggle 2FA qua wp-cli (chỉ ground truth) |

**Bảng tiền điều kiện:**
| Tiền điều kiện | Dấu hiệu HTTP dự kiến | Cách thu | Chỉ ground truth |
|---|---|---|---|
| plugin version ∈ dải | version trong asset URL / readme | `GET /wp-content/plugins/really-simple-ssl/...` | version thật (wp-cli/DB) |
| 2FA bật | **chưa rõ** (khảo sát login page + REST route) | ≤20 req: `/`, `/wp-login.php`, `/wp-json/` | cờ 2FA trong setting |

**Path chốt trước:** `/`, `/wp-login.php`, `/wp-json/`, `/wp-json/reallysimplesecurity/...`
(điều tra route), asset plugin.

**Câu hỏi pilot:** "2FA bật" quan sát được unauthenticated không? Nếu không → phương pháp trả
Unknown trên ca Applicable (đo cost-of-miss, R2).

**Reproduce (ground truth):** cài bản lỗi + 2FA bật, chạy PoC bypass login qua REST, ghi
request/response/log. Chạy lại trên bản fixed 9.1.2 → phải **không** bypass được (đối chứng).

## Ca B — Drupal CVE-2019-6340 (RCE qua REST/web-services)

| Mục | Giá trị |
|---|---|
| Bản lỗi | Drupal 8.6.9 (∈ 8.6.x < 8.6.10) |
| Bản fixed | 8.6.10 |
| Trạng thái config | (i) REST core bật; (ii) REST tắt + **JSON:API bật**; (iii) cả hai tắt |
| Access model | **authenticated** (tài khoản có quyền tạo content — tiền điều kiện thật của CVE; xem D-015) |
| Fixture | content type + fields đủ điều kiện; toggle module qua `drush` (ground truth) |

**Bảng tiền điều kiện:**
| Tiền điều kiện | Dấu hiệu | Cách thu | Ground truth |
|---|---|---|---|
| REST core bật | `/node/1?_format=json` → JSON ≠ 404 | probe | module list |
| JSON:API bật | `/jsonapi/node/article` → JSON | probe | module list |
| version | header / CHANGELOG | probe | version thật |

**Câu hỏi pilot:** trạng thái (ii) — tắt REST core nhưng JSON:API còn — vẫn applicable? Kiểm
chứng "một đường tắt chưa đủ" (nhánh b). Trạng thái (iii) → Not Applicable thật.

## Ca C — Roundcube CVE-2020-12625 (XSS) — tách 2 luồng

| Mục | Giá trị |
|---|---|
| Bản lỗi | Roundcube 1.4.3 (∈ < 1.4.4) |
| Bản fixed | 1.4.4 |
| Access model | **tách 2 model**: (U) unauthenticated; (A) authenticated (tài khoản thường) |
| Fixture | mailbox + email HTML chứa payload (fixture reproduction); reset mailbox/cookie giữa lần chạy |

**Hai luồng tách bạch:**
1. **Reproduction (ground truth):** payload do nhóm tự đặt + browser runner (Playwright/
   Chromium) xác nhận **thực thi XSS** trên bản lỗi; chạy lại bản fixed 1.4.4 → không thực thi.
2. **Quan sát phương pháp (độc lập):** chỉ dấu hiệu HTTP thu được **không kích hoạt lỗi** —
   version (header/INSTALL), login page, và (nếu model A) email HTML. **Không cấp fixture
   payload / kết quả browser cho fusion.**

**Bảng tiền điều kiện (theo model):**
| Tiền điều kiện | Dấu hiệu | Model | Ground truth |
|---|---|---|---|
| version < 1.4.4 | header / INSTALL / CHANGELOG | U + A | version thật |
| khả năng xem email ở chế độ HTML | giao diện/chế độ xem HTML với email thử nghiệm lành tính; chưa tự chứng minh XSS | **chỉ A** | fixture payload và bằng chứng thực thi trên browser chỉ dùng cho reproduction |

**Câu hỏi pilot:** model U có quan sát được điều kiện liên quan đến chế độ xem HTML không?
Nếu chưa đủ bằng chứng để kết luận applicability → phương pháp giữ Unknown. Model A có
thể quan sát chế độ xem bằng email lành tính, nhưng điều đó chưa chứng minh XSS. Payload
và kết quả thực thi trên browser thuộc ground truth, không đưa vào dấu hiệu của phương
pháp. Ghi nhận giới hạn observability theo từng model, không gộp.

## Tiêu chí hoàn thành pilot

1. Mỗi ca ghi được: **tái tạo được/không**, **dấu hiệu HTTP thu được** (và độ đặc hiệu),
   **đường nào quan sát được / không**.
2. Ca không dựng được / không quan sát được = **kết quả hợp lệ**, ghi nguyên nhân, không chọn
   lại ca khác cho đến khi "đẹp".
3. Kết luận được access model nào khả thi cho benchmark ≥30 CVE.

## Sau pilot

Chốt subset sản phẩm/plugin + criterion chọn + registry ≥30 CVE khác nhau. Tách phần chỉnh
luật khỏi phần đánh giá; không dùng kết quả pilot đã học để tuyên bố hiệu quả trên dữ liệu
chưa thấy.
