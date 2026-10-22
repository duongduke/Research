# Cheat-sheet — trước khi gặp thầy hướng dẫn (09/10/2026)

## Tên đề tài
Đánh giá khả năng áp dụng CVE cho mục tiêu web bằng cách kết hợp nhiều nguồn bằng chứng.

## Giải thích trong 30 giây
> "Một CVE khi công bố chỉ ảnh hưởng một số phiên bản nhất định, nhưng trùng phiên bản chưa chắc đã dính.
> Đồ án trả lời: một CVE có **thực sự áp dụng** cho triển khai web đang chạy hay không.
> Em so sánh cách dùng **một nguồn dữ liệu** với cách **kết hợp nhiều nguồn** để giảm kết luận sai,
> đo trên bộ CVE có nhãn chuẩn kiểm chứng được."

## Ba mức kết luận
| Mức | Nghĩa |
|---|---|
| 1. Ảnh hưởng bản phần mềm | version nằm trong dải affected |
| 2. **Áp dụng cho triển khai cụ thể** | cấu hình thực tế có chạm vào điểm lỗi — **em chọn đây** |
| 3. Đã khai thác thành công | PoC chạy được trên mục tiêu |

- Vì sao mức 2: mức 3 vượt policy + đụng hệ thống thật; mức 1 false positive rất cao.
- Thiếu bằng chứng → trả "Unknown", không được coi là an toàn.

## Phương pháp
- **Benchmark:** ~30 CVE khác nhau, mỗi CVE thử nhiều (version × cấu hình);
  nhãn chuẩn bằng **tái tạo trong sandbox của mình** (không đụng mục tiêu thật).
- **So sánh:** 4 nguồn đơn (CPE / NVD / advisory / version-string) + kết hợp nhiều nguồn.
- **Chỉ số:** precision, recall, F1, coverage (tỷ lệ kết luận được), tỷ lệ Unknown, số kết luận sai.

## Đã làm được
- Đọc 2 bài báo (VAVI, Vuln2Action), thiết kế protocol đánh giá.
- Dựng lab Docker; **tái tạo xong 3 CVE** (9 trạng thái đã có nhãn chuẩn).
- Chốt danh sách **30 CVE** (đa dạng loại lỗi: SQLi, XSS, RCE, path traversal, auth bypass...).

## Điểm mới (khác công cụ hiện có)
1. Công cụ hiện nay chủ yếu dừng ở **mức 1** (khớp version) → false positive cao.
2. Của em: quyết định ở **mức 2**, kết hợp nhiều nguồn + quan sát HTTP,
   và có **ground truth kiểm chứng bằng thực thi** — điều 2 bài tham khảo đều thiếu
   (VAVI chỉ làm mức 1, Vuln2Action không chạy kiểm chứng).

## Ba câu hỏi cho thầy
1. "Em dừng ở mức 2 (không khai thác mục tiêu thật; lab tái tạo trong sandbox để chấm nhãn) — thầy thấy phạm vi này ổn không?"
2. "So sánh 4 nguồn đơn + kết hợp trên ~30 CVE có vừa sức đồ án tốt nghiệp không, thầy muốn em thêm/bớt gì?"
3. "Có yêu cầu nào về tiến độ, format báo cáo hay mốc bảo vệ em cần lưu ý không?"
