# Đối chiếu bản mapping đã khóa D-030 — 14/10/2026

Đã đọc ruling G1–G7 và các sửa bổ sung §7, D-030, mapping header và context.
Kiểm tra read-only trên file đã khóa; không sửa mapping, raw snapshot, nhãn hoặc
quyết định đã ACCEPTED. Không chạy lab hoặc implementation của các method.

## Kết quả kiểm tra độc lập

- SHA256 file đúng D-030:
  `f266673ee3f1b2d6ae14b0ac2357a550d63a4013b4eb7f1e8676509248d7fbd1`.
- 2.363 dòng, 30 section CVE và 30 block YAML.
- 56 probe: 18 verified, 34 pending, 4 needs_control.
- Không còn NOT trong all_of hoặc path_config_off.
- Quét tham chiếu/kind trên 31 đường: không thấy condition ID thiếu hoặc condition
  có kind khác precondition nằm trong all_of.

Quét cuối dùng cấu trúc text của block; không phải một YAML parser. Không chạy
lại parser độc lập trong lượt này, không audit lại toàn bộ semantics/capture
validation của 56 probe. Kết quả này xác nhận bản đã ghi và các invariant được
kiểm, không xác nhận hiệu năng phương pháp hay nâng D-011 lên ACCEPTED.

## Chuyển sang bước 3

Có thể giao engineer triển khai năm method và harness theo đúng D-026/D-030.
Yêu cầu cài đặt lấy từ quyết định hiện có:

1. Kiểm hash/version của mapping và snapshot manifest khi nạp; ghi chúng trong
   run metadata để biết chính xác dữ liệu/rule đã dùng.
2. Collector giữ observed product/component/version và provenance; từng method
   chọn đúng source/evidence được phép. Giữ duplicated baselines khi cùng input.
3. Cổng G7: pending/needs_control không tạo True/False hoặc giá trị E5 dùng quyết
   định từ capture chưa được chấp nhận; runtime vẫn giữ Unknown theo bản khóa.
4. B và P_i riêng; blocked paths không đòi B=True khi target đúng/phạm vi đủ;
   missing data/conflict không tự tạo nhãn âm. Không thêm fallback lấy GT.
5. Loader/evaluation tách GT/config nội bộ khỏi input method. Ghép labels sau
   prediction để chấm, không đưa label hay installed package metadata vào B/P_i.
6. Case là product/build/config/CVE/access scope đã mô tả. 28 là số CVE IDs đã
   resolved trong registry, không phải số case; báo n_unique_cves/n_cases/labels
   riêng. Case Unresolved không tham gia mẫu số metric có GT và báo riêng.
7. Metric theo công thức đã ghi: recall/F1 giữ U_A, tách FN_def và abstention,
   cùng mẫu số coverage/Unknown rate, mẫu số 0 theo chính sách N/A đã chốt.

Các kiểm tra cài đặt đáng làm trước full comparison: inclusive/exclusive/exact
version boundaries; component/source filtering; B/P_i và Unknown gate; label
isolation; metric với U_A và mẫu số 0; hash mismatch. Dùng fixture tổng hợp cho
logic trước, không chỉnh cutoff/mapping sau khi xem kết quả benchmark.

Sau khi code/harness vượt các kiểm tra phù hợp, mới chạy so sánh và lưu raw
captures/predictions riêng khỏi bảng metric/phân tích. Nhiều Unknown là kết quả
cần đo của phiên bản này, không phải lý do tự nâng validation hoặc vá theo đáp án.
