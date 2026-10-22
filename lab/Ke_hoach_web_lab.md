# Đánh giá VM và đề xuất web lab

Kiểm tra read-only qua SSH ngày 30/09/2026, khoảng 06:52 giờ Việt Nam. Không dùng WSL làm máy đích và không cài/thay đổi dịch vụ trong lần kiểm tra này.

## 1. Trạng thái đã quan sát

| Hạng mục | Kết quả |
|---|---|
| Máy đích | <lab-user>@<lab-ip> |
| OS | Ubuntu 22.04.5 LTS, x86_64; kernel 6.8.0-138-generic |
| CPU khả dụng | 2 |
| RAM | Tổng 3,8 GiB; available khoảng 2,4 GiB |
| Phân vùng `/` | 20 GB; còn khoảng 5,1 GB; dùng 73% |
| Công cụ dịch vụ | `command -v docker nginx apache2` không trả đường dẫn |
| Trạng thái dịch vụ | docker/nginx/apache2 đều inactive theo systemctl |
| Cổng TCP lắng nghe | 22, DNS loopback 53, CUPS loopback 631; không thấy 80/443/8080 |
| NIC | ens33: <lab-ip>/24; ens37: <lab-ip>/24 |

Login banner báo cần restart. Không reboot tự động. Chưa kiểm tra routing/firewall hoặc VMware adapter mode, nên chưa xác nhận lab đã cách ly mạng.

## 2. Có thể dùng VM này không?

Có: theo tài nguyên hiện tại, một web lab nhỏ, chạy tuần tự từng cấu hình là khả thi. Đây là đánh giá thiết kế, chưa phải benchmark hay xác nhận dịch vụ đã triển khai.

Ubuntu có hướng dẫn chính thức dùng Nginx cho web services: https://ubuntu.com/server/docs/how-to/web-services/install-nginx/. Docker Engine hỗ trợ Ubuntu Jammy 22.04 amd64: https://docs.docker.com/engine/install/ubuntu/.

Hạn chế chính là dung lượng trống. Nên mở rộng disk hoặc chỉ dùng vài image nhỏ, kiểm tra dung lượng trước khi kéo image; không tự xóa dữ liệu cũ trên VM. Chưa cần LLM/GPU, một WAF thật hay nhiều ứng dụng chạy đồng thời cho bước đầu.

## 3. Thiết kế đề xuất

```text
Máy Windows / scanner --HTTP--> VM Ubuntu: web mục tiêu (+ proxy nếu cần)
                                |
                                +-- hồ sơ version/config thật để chấm riêng
```

Máy đích phục vụ website; công cụ nhận diện/đối chiếu CVE không nhận thông tin đặc quyền từ SSH. SSH chỉ dành cho quản trị lab và thu ground truth.

Đề xuất dùng container với version/digest cố định khi chọn được sản phẩm, để thay phiên bản mà không phải downgrade gói hệ điều hành. Có thể chạy lần lượt hoặc tách cổng cho các biến thể. Không dùng tag `latest` làm định danh thí nghiệm.

Trước triển khai, kiểm tra NIC/routing và giữ lab trong mạng dành riêng cho host-lab; không port-forward ra Internet. Chọn rõ IP bind thay vì mặc định mọi interface, vì VM đang có hai NIC. Docker cảnh báo publish port có thể vượt qua quy tắc UFW; không coi chỉ bật UFW là đã cô lập: https://docs.docker.com/engine/install/ubuntu/#firewall-limitations.

## 4. Thử nghiệm đầu tiên cần tạo ra gì?

Một cấu hình là một bản triển khai có sản phẩm, version, config và cách hiển thị version đã biết. Các biến thể ban đầu:

| Biến thể | Điều thay đổi | Mục đích |
|---|---|---|
| Công khai version | Header/trang thông tin hiển thị version | Kiểm tra baseline có đọc đúng không |
| Ẩn version | Cùng phần mềm nhưng bỏ dấu hiệu version công khai | Kiểm tra mất banner có làm đoán sai/Unknown không |
| Qua reverse proxy | Header ngoài thuộc proxy, backend giữ nguyên | Kiểm tra có nhầm version proxy thành version ứng dụng không |

Ẩn header không tương đương với một WAF thực tế. Các biến thể này trước hết kiểm tra thu thập/nhận diện HTTP; chưa chứng minh CVE tồn tại hoặc độ chính xác CVE tăng.

Bước sau chọn ít nhất một sản phẩm web có CVE/advisory chính thức và các bản phát hành dựng được, tạo cặp affected/fixed với config phù hợp. Không chọn CVE chỉ vì có PoC nổi tiếng. Cần lưu nguồn phiên bản, image digest, config, điều kiện CVE và bằng chứng nhãn. Trang đào tạo cố ý có lỗi cũng không tự động tương ứng với một CVE của sản phẩm/version thật.

## 5. Cách chứng minh và giới hạn

- Nhận diện: đối chiếu version/range dự đoán từ HTTP với version thật lưu riêng; báo cả Unknown.
- CVE affected: đối chiếu advisory, phiên bản và điều kiện triển khai; chưa gọi là khai thác được nếu thiếu điều kiện/runtime evidence.
- Reproduction thành công có thể củng cố một nhãn positive trong lab. PoC thất bại không tự chứng minh negative: có thể sai môi trường, tham số, authentication hoặc payload.
- Hai phương pháp so sánh cụ thể phụ thuộc hướng 1/2/3 được chọn; mô tả trong ghi chú đọc paper, chưa chốt thay trợ giảng.

## 6. Thứ tự tiếp theo đề xuất

1. Chốt mục tiêu thử nghiệm trước: thu HTTP từ một sản phẩm web và so với thông tin thật, không tuyên bố đã chốt toàn bộ scope.
2. Xác nhận NIC/cách ly, snapshot trạng thái hiện tại và phương án dung lượng.
3. Triển khai một web mục tiêu nhỏ; kiểm tra từ Windows bằng HTTP; lưu response và thông tin cấu hình.
4. Thử công khai/ẩn version. Sau đó chọn sản phẩm/CVE thật và cặp affected/fixed để mở rộng.
5. Đưa trợ giảng bản đọc hai bài, sơ đồ lab, dữ liệu quan sát được và câu hỏi chọn hướng. Không gửi brief OpenSSH cũ như tiến độ hiện tại.

Trạng thái cuối lần làm việc này: bước đọc và đánh giá VM đã xong; bước triển khai web chưa thực hiện.
