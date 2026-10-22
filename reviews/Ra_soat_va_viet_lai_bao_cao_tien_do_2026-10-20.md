# Rà soát và viết lại báo cáo tiến độ ngày 19/10/2026

Ngày chỉnh sửa: 20/10/2026. Phạm vi: biên tập báo cáo theo yêu cầu người dùng, đối chiếu dữ kiện đã có; không chạy lại lab hoặc benchmark, không thay đổi phương pháp hay nhãn.

## Tài liệu và dữ liệu đối chiếu

Đã đọc vai trò researcher tại `.opencode/agents/researcher.md`, bộ nhớ dự án, đề cương, bản báo cáo cũ, luật fusion, protocol, ghi chú hai bài báo ban đầu, ghi chú khảo sát fusion và phân tích U_A. Dữ kiện thực nghiệm được đối chiếu trực tiếp với:

- `experiments/methods/output/benchmark-v3/{metrics,predictions,run-metadata}.json` và hai thư mục kết quả V1/V2 tương ứng.
- `experiments/methods/data/cases.json`, `observations.json`, bảng `notes/collector-mapping-30cve.md`.
- `experiments/methods/fixture/output/fixture-report.json`: 193/193 là kết quả đã lưu, không phải lần kiểm thử mới trong phiên này.
- Hồ sơ lab và các quyết định đã chấp nhận, đặc biệt D-024, D-026, D-034–D-037.

## Những điểm đã sửa

| Bản trước | Cách thể hiện trong bản mới | Căn cứ |
|---|---|---|
| Liệt kê công việc và thuật ngữ nội bộ | Trình bày mục tiêu, lý do cần kiểm điều kiện triển khai, công việc, kết quả, hạn chế và kế hoạch | Đề cương và luật fusion |
| “Tái hiện 32 CVE” | 32 ID; 30 có nhãn xác định, 2 XSS Unresolved; 69 trường hợp, N tính điểm = 67 | cases.json, metadata V3, D-036/D-037 |
| “Không bao giờ dương tính giả” | Chưa ghi nhận FP trên V3; precision 1.0 dựa trên 6 kết luận dương | metrics.json |
| Bảng thiếu số, gom baseline nhưng chưa giải thích | Đủ 5 phương pháp, precision/recall/F1/coverage/Unknown/FP; N/A khi không có kết luận dương | metrics.json |
| Quy toàn bộ recall thấp cho giới hạn HTTP, loại trừ lỗi hiện thực | Phân biệt thiếu bản ghi, thiếu đầu dò, hạn chế mapping và khả năng quan sát; kiểm thử không bảo đảm không còn lỗi | note U_A, mapping, fixture |
| “20 ca mang tính cấu trúc” | Giới hạn theo bảng tín hiệu và thiết kế hiện tại; không chứng minh bất khả quan sát HTTP nói chung | note U_A §9 |
| Hai XSS cùng do SVG | 5631: SVG/browser; 6341: đã lưu tệp nhưng trình duyệt xem text/plain, các đường khác còn vướng cấu hình/lưu trữ | CURRENT_STATE §36–37, README 6341 |
| V1→V2→V3 dễ đọc như cải tiến trên cùng tập | V1/V2 cùng N62; V3 thêm 5 trường hợp, N67; không dự đoán cũ nào đổi từ V2 sang V3 | join predictions V2/V3 và metrics |
| Thiếu hạn chế về dữ liệu phát triển | Nêu phụ thuộc giữa các trường hợp cùng CVE và việc một phần dữ liệu đã dùng để xây luật/tín hiệu | metrics by_group; mapping development_use |
| Cam kết so sánh ngoài với VAVI/Vuln2Action | Xếp hai bài vào khảo sát; công cụ so sánh bổ sung cần cùng bài toán/đầu vào/đầu ra | notes hai bài, handoff lịch sử |

Bản mới cũng nêu một giới hạn đã thể hiện trong bảng tín hiệu: đầu dò Joomla đọc cấu hình không xác thực và có thể trực tiếp quan sát tác động tiết lộ thông tin. Vì vậy chưa khẳng định mọi phép kiểm tra đều nằm trong phạm vi “không khai thác trực tiếp”. Đây là vấn đề cần làm rõ, không phải quyết định thay phương pháp trong phiên này.

## Số liệu V3 đã kiểm tra

| Phương pháp | TP | FP | TN | Unknown | Precision | Recall | F1 | Bao phủ |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CPE / NVD / HTTP-version (cùng vector) | 13 | 3 | 11 | 40 | 0.8125 | 0.41935 | 0.55319 | 0.40299 |
| Advisory | 0 | 0 | 10 | 57 | N/A | 0 | 0 | 0.14925 |
| Fusion | 6 | 0 | 13 | 48 | 1 | 0.19355 | 0.32432 | 0.28358 |

Fusion Unknown = 25 nhãn Applicable + 23 nhãn Not Applicable. FN_def = 0 ở cả năm phương pháp. Nhóm rule development có 12 trường hợp; signal development 13; no_development có 44, trong đó 42 được tính điểm. Không gọi nhóm cuối là held-out nếu chưa có căn cứ về sự tách biệt.

## Đầu ra và kiểm tra

- Bản nội dung: `notes/bao-cao-tien-do-2026-10-19.md`.
- Nguồn và PDF: `research/bao-cao-tien-do-2026-10-19/bao-cao-tien-do-2026-10-19.{tex,pdf}`.
- Giữ ngày báo cáo 19/10/2026; chỉnh biên tập thực hiện ngày 20/10/2026. Không thêm diễn biến lab sau mốc báo cáo.
- Bản trước khi sửa lưu tại `tmp/pdfs/bao-cao-rewrite-2026-10-20/before/`.
- PDF LuaLaTeX hai lượt, 3 trang A4; đã xem cả ba trang, xác nhận tiếng Việt và bảng kết quả hiển thị đúng. Log cuối không có Overfull/Underfull, missing character, warning hay lỗi LaTeX; trích xuất PDF kiểm tra các số liệu chính và số trang.
- Hash bảng mapping vẫn là `c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c`; hash metrics V3 vẫn là `8070352303102028a9b21e82e02556e5b1f1aebb99a9b2f2bfbf236d8f2ef2c3`.
- Không sửa snapshot, dự đoán, nhãn, chương trình đánh giá, quyết định đã chấp nhận, `legacy/` hoặc handoff lịch sử. Các việc ở phần kế hoạch là việc tiếp theo, chưa được thực hiện bởi lần biên tập này.

### Điều chỉnh cỡ chữ theo phản hồi tiếp theo

Người dùng yêu cầu chữ cỡ 13–14. Đã đổi nội dung, bảng và phần nguồn sang 13 pt; tiêu đề mục 14 pt, mục con 13 pt; bỏ thu nhỏ phông đơn cách. PDF sau điều chỉnh có 4 trang A4. Đã đối chiếu nội dung TeX trước/sau (chỉ khác phông và lệnh dàn trang), kiểm tra kích thước chữ thực trong PDF, biên dịch hai lượt và xem các trang. Không còn cảnh báo phông hoặc tràn dòng. Bản 3 trang trước điều chỉnh được lưu ở `tmp/pdfs/bao-cao-font-13-2026-10-20/before/`.

### Thống nhất thuật ngữ theo phản hồi tiếp theo

Đã dùng đúng năm tên CPE-only, NVD-only, Advisory-only, HTTP version-string-only và Fusion trong bảng và phần diễn giải. Labels giữ Applicable / Not Applicable / Unknown, ground truth chưa xác định giữ Unresolved. Các thuật ngữ kỹ thuật dùng English trong prose Việt, lược phần dịch/giải nghĩa dài; cột phần trăm Unknown đổi tên chính xác thành Unknown rate, cột cảnh báo sai thành FP. Tất cả giá trị số trong bảng được đối chiếu trước/sau và giữ nguyên. Các giới hạn và ý nghĩa kết quả không thay đổi. Đã đồng bộ Markdown, TeX, PDF; giữ chữ 13–14 pt, kiểm tra cả bốn trang, không có cảnh báo LaTeX. Bản trước sửa thuật ngữ lưu ở `tmp/pdfs/bao-cao-terms-2026-10-20/before/`.

### Cân bằng lại tiếng Anh và tiếng Việt theo phản hồi mới nhất

Người dùng nhận xét bản trên lạm dụng tiếng Anh. Đã giữ tiếng Anh cho tên phương pháp, các nhãn và tên chỉ số; những khái niệm cần liên hệ tài liệu được chú thích tiếng Anh lần đầu rồi dùng tiếng Việt. Phần diễn giải chuyển về “bộ dữ liệu”, “trường hợp đánh giá”, “bằng chứng”, “tái hiện tác động”, “kiểm chứng”, “bản phần mềm cụ thể”, “đầu vào/đầu ra” và “tập đánh giá tách khỏi quá trình phát triển”. Các cách dịch giữ phân biệt build với version, kiểm chứng đầu dò với tái hiện tác động, trường hợp đánh giá với mã CVE và Unknown với Unresolved. Không thay số liệu hoặc phương pháp. Đã đồng bộ Markdown/TeX/PDF, kiểm tra toàn bộ 4 trang và cỡ chữ tối thiểu 13 pt; log cuối không có cảnh báo. Bản trước chỉnh lưu ở `tmp/pdfs/bao-cao-balanced-terms-2026-10-20/before/`.

### Bổ sung phụ lục 32 CVE

Theo yêu cầu tiếp theo, đã thêm Phụ lục A và dẫn chiếu từ mục 2.2. Phần chính được giữ nguyên ngoài câu dẫn chiếu; phụ lục trình bày cơ chế, điều kiện quan trọng, các phiên bản lab và kết quả kiểm chứng. Quy ước A/NA được giải thích là Applicable/Not Applicable; Unresolved được ghi đầy đủ ở hai CVE chưa có nhãn chuẩn.

| Nhóm | Số CVE | Căn cứ đối chiếu |
|---|---:|---|
| WordPress core | 6 | README theo mã CVE tại `experiments/26cve/` |
| Plugin WordPress | 10 | README tại `experiments/26cve/`; hồ sơ thí điểm 10924 và hồ sơ bổ sung 6553 |
| Drupal core | 6 | README tại `experiments/26cve/`; hồ sơ thí điểm 6340; nhãn cuối D-024 |
| Roundcube | 6 | README tại `experiments/26cve/`; hồ sơ thí điểm 12625; phần REWORK 5631 và D-024 |
| Apache/nginx | 3 | `experiments/reproduce-cve-2021-41773/`; README 42013, 23017; D-020/D-031 |
| Joomla | 1 | `experiments/topup-2026-10-17/cases/CVE-2023-23752/README.md`; registry Appendix F và D-036 |

Đã đối chiếu tập ID với `experiments/methods/data/cases.json`: đúng 32 ID, mỗi ID một dòng, không đưa các ứng viên đã loại/thay thế vào phụ lục. Đối chiếu văn bản trích từ PDF cũng tìm thấy đúng 32 ID ở phần phụ lục; hai Unresolved là CVE-2019-6341 và CVE-2023-5631. Các phiên bản trong bảng là phiên bản lab, không được trình bày như toàn bộ dải ảnh hưởng.

Đã giữ rõ các giới hạn: 2745 mới chứng minh tải tệp dịch; 13671 mới kiểm chứng xử lý tên tệp, chưa RCE hoàn chỉnh; 12640 cần tệp cục bộ đặt sẵn và cấu hình mô phỏng; nginx chỉ xác minh bản đã vá; 41773 là đối chứng thăm dò; 28000 cung cấp hash từ DB; 6553 có cả trạng thái bật và tắt nhưng còn tệp. Các ghi chú này không thay nhãn hoặc phương pháp đã chấp nhận.

PDF cuối có 10 trang, phụ lục bắt đầu trang 5, các nhóm A.1–A.6 có tiêu đề bảng lặp khi qua trang. Đã kiểm tra cả 10 trang, phông tối thiểu 13 pt, nhãn liên kết mục 2.2 tới Phụ lục A, log biên dịch không có cảnh báo. Hash mapping và metrics V3 giữ nguyên. Bản trước bổ sung được lưu tại `tmp/pdfs/bao-cao-appendix-2026-10-20/before/`.
