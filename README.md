# RQ-C1: nghiên cứu CVE đối với mục tiêu web

Cập nhật: 30/09/2026. Đây là trạng thái làm việc, chưa phải scope nghiên cứu đã chốt với trợ giảng.

## Điều đã được xác nhận

Theo phản hồi của trợ giảng, mục tiêu của RQ-C1 là web interface/web-facing target. Thử nghiệm OpenSSH và inventory gói Ubuntu trước đây không phù hợp để làm thí nghiệm chính.

Ba hướng trợ giảng nêu: nhận diện phiên bản hoặc khoảng phiên bản; bổ sung bằng chứng để ưu tiên CVE; kiểm chứng khả năng áp dụng CVE mà không trực tiếp khai thác. Chưa tự chọn một hướng thay cho trợ giảng.

## Tài liệu hiện tại

- `paper/`: hai bài báo gốc, giữ nguyên file người dùng cung cấp.
- `notes/Doc_hai_bai_RQ_C1_2026-09-30.md`: phương pháp, kết quả, giới hạn và liên hệ với bài toán web.
- `lab/Ke_hoach_web_lab.md`: kiểm tra VM thực tế và đề xuất lab, chưa triển khai.
- `legacy/ubuntu-package-cve/`: toàn bộ 46 mục cấp đầu của thử nghiệm cũ, không xóa dữ liệu.

## Trạng thái triển khai

Đã đọc hai bài và kiểm tra VM qua SSH, không dùng WSL để thay thế máy đích. Chưa cài web server, Docker, ứng dụng web hay chạy PoC trong công việc chuyển hướng này. Chưa có kết quả so sánh phương pháp trong scope web, cũng chưa chứng minh cải thiện độ chính xác.

Bước kế tiếp đề xuất: dựng một mục tiêu web nhỏ để thu HTTP và đối chiếu với cấu hình thật; sau đó chọn sản phẩm/CVE có nguồn chính thức và cặp phiên bản kiểm chứng được. Việc dựng lab ban đầu không đồng nghĩa với chốt thu hẹp đề tài.
