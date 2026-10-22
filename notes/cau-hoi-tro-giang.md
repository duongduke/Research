# Câu hỏi gửi trợ giảng (chốt hướng + độ sâu)

> Ngày: 06/10/2026. Bộ câu hỏi này để **chốt hướng và độ sâu kết luận** trước khi
> đi vào thiết kế chi tiết (dataset / baseline / metric).
> Chưa gửi — đang chờ người dùng gửi.

## Bối cảnh ngắn (mở đầu tin nhắn)

> Em hiểu câu hỏi gốc là: *kiểm tra một CVE có thực sự ảnh hưởng đến
> product/version đã phát hiện, bằng cách kết hợp nhiều nguồn bằng chứng*. Em đề
> xuất đánh giá **fusion nhiều nguồn so với baseline đơn nguồn trên cùng
> benchmark**, với lab hỗ trợ kiểm chứng một tập con (em đã dựng lab và reproduce
> được CVE-2021-41773). Trước khi làm tiếp, em cần thống nhất vài điểm.

## Câu hỏi

**1. Về hướng đi.** Em hiểu hướng 3 ("validate CVE khả thi mà không cần khai
thác") gần với câu hỏi gốc nhất. Em định làm **hướng 3 thu hẹp scope**: kết hợp
nhiều nguồn bằng chứng → Applicable / Not Applicable / Unknown, rồi đo
accuracy/precision/recall so với nguồn lẻ. Vậy **làm trọn hướng 3 là đúng chuẩn
đề tài**, hay đồ án chỉ cần đạt hướng 1 hoặc 2 là được?

**2. Về độ sâu kết luận.** Em hiểu có 3 mức: (1) CVE ảnh hưởng *bản phần mềm*,
(2) CVE áp dụng cho *triển khai cụ thể* (kèm cấu hình/tiền điều kiện),
(3) *đã khai thác thành công*. Em dự định kết luận ở **mức 2**. Vậy chữ "khả thi"
thầy nói là **mức 2 (applicable)** hay **mức 3 (exploitable)**?

**3. Về phạm vi "web interface".** Chỉ web server, hay cả backend framework /
web app / CMS / reverse proxy? Em đang định nghĩa 4 nhóm như vậy — có cần thu hẹp?

**4. Về ground truth.** Nhãn "Applicable" lấy từ đâu: chỉ dữ liệu công khai
(NVD/CPE/vendor advisory/patch), hay cần thêm source/binary evidence?

**5. Về reproduce lab.** Việc tái tạo lỗi trong sandbox là **bắt buộc** (để tạo
ground truth), **tùy chọn**, hay **ngoài phạm vi**? Bao nhiêu CVE reproduce là đủ?

## Ghi chú nội bộ

- **Quan trọng nhất: câu 1 và 2** (quyết định hướng + độ sâu). Câu 3–5 là chi tiết scope.
- Cách đặt: "em hiểu thế này... đúng không?" + kèm lựa chọn — đúng tinh thần
  trợ giảng muốn (chủ động hiểu, không hỏi mơ hồ).
- Nếu trợ giảng trả lời câu 1 = "hướng 3 đúng" và câu 2 = "mức 2", thì thiết kế
  hiện có (fusion + config evidence + reproduce lab) là chuẩn, chỉ cần chốt thêm
  scope sản phẩm + số CVE.
