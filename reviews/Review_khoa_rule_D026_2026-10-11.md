# Review trạng thái khóa rule D-026 — 11/10/2026

Phạm vi: D-026, bản KHÓA của `notes/fusion-design-2026-10-10.md`, protocol,
context và danh mục artifact trong workspace. Không sửa bộ rule đã khóa, không
chạy lab hoặc phương pháp trên benchmark. Các đề xuất ghi ở **D-027 PROVISIONAL**.

## Kết luận

D-026 đã chốt ý định đóng băng rule, ngày snapshot và bộ metric. Giữ nguyên quyết
định này. Tuy nhiên, bản text chưa xác định một thuật toán duy nhất ở nhánh thiếu
version; mapping HTTP→predicate chưa hoàn tất; artifact snapshot chưa tìm thấy.
“Đã khóa rule” chưa đồng nghĩa implementation và evaluation contract đã đầy đủ.

## R1 — Ba cách diễn đạt cho kết quả khác nhau

- Bản tóm tắt người dùng: `B=False` **hoặc** mọi `P_i=False` với phạm vi đủ → NA.
- File rule §4, dòng 100: nhánh mọi `P_i=False` còn yêu cầu **B=True**.
- File rule §4, dòng 84: không xác định được version → **Unknown ngay tầng 1**.

Ví dụ giả định: sản phẩm/access model đã nhận diện, chưa biết version/build,
nhưng phạm vi các đường tác động đã xác định đủ và từng đường đều có điều kiện
bắt buộc được xác nhận False. Công thức trong tóm tắt cho NA; hai cách viết trong
file có thể cho Unknown. Đây là khác biệt ngữ nghĩa, không chỉ khác văn phong.

**Đề xuất:** tầng thu thập nhận diện có thể gán trạng thái chưa rõ, nhưng chỉ trả
Unknown cuối cùng khi không có nhánh quyết định đủ căn cứ. Viết một quy tắc
canonical B/P_i; nhánh config-blocked không cần B=True nếu phạm vi đường đủ và
đúng target. Không áp dụng phép suy này khi chưa nhận diện sản phẩm/phạm vi.
Việc sửa semantic cần amendment/version mới trước đánh giá, không tự ghi đè bản
đã khóa. Review này chưa thực hiện amendment.

## R2 — Thứ tự nhánh và dữ liệu thiếu cần quy định khi triển khai

Advisory-only liệt kê Unknown do thiếu precondition ở bước 3, Applicable ở bước
4 và kiểm bản vá ở bước 5. Nếu chuyển trực tiếp thành chuỗi if/elif, bản vá đã
xác minh có thể không bao giờ được xét. Cần định rõ ưu tiên: bằng chứng build đã
vá đáng tin đủ cho NA, không bị nhánh thiếu precondition chặn trước.

Tương tự, version đã biết nhưng không có bản ghi CVE/CPE, range không parse được
hoặc product matching chưa xác định không phải bằng chứng version nằm ngoài
dải. Đề xuất giữ Unknown cho dữ liệu thiếu/không diễn giải được. Predicate chưa
giải được hoặc mâu thuẫn cũng không mặc định làm kết luận cuối Unknown nếu một
nhánh độc lập khác đã đủ căn cứ; ghi rõ quy tắc tổng hợp.

## R3 — Bảng signal gồm cả tri thức CVE và quy tắc đo, không chỉ raw input

Tách hai phần:

- Tri thức công khai theo CVE: affected range, preconditions, patch references.
- Collector và mapping: request/path, access model, budget, cách response trở
  thành True/False/Unknown, điều kiện loại trừ proxy/auth/cache hoặc nhập nhằng.

Phần thứ hai là một bộ phận của phương pháp. Thay probe hay cách diễn giải sau
khi xem kết quả có thể thay dự đoán dù B/P_i không đổi. Cần khóa cả collector,
mapping và dữ liệu tham chiếu trước evaluation, lưu version/hash và lịch sử sửa.

D-026 gọi 28 resolved là “clean evaluation set”, nhưng số này có cả CVE pilot
đã dùng để phát triển thiết kế. Những ca dùng xác minh/tinh chỉnh signal cũng
cần ghi nhận là development, không tự trở thành held-out vì chưa tính metrics.
Chỉ đọc advisory theo quy trình cố định không tự là leakage; dùng trạng thái
ground truth để chọn dấu hiệu riêng có lợi cho từng ca thì có nguy cơ leakage.

Vẫn có thể so sánh trên benchmark hiện có và báo đầy đủ ca đã dùng phát triển;
không cần tự tạo thêm một quota CVE. Không gọi toàn bộ kết quả là đánh giá trên
các CVE hoàn toàn chưa được dùng trong thiết kế nếu không có phân nhóm chứng minh.

## R4 — Snapshot cần artifact có thể nạp lại

Trong danh mục file và tìm kiếm snapshot/manifest/JSON/HTML/CSV đã kiểm tra, chưa
tìm thấy bộ dữ liệu CPE/NVD/advisory snapshot kèm manifest; các JSON/HTML tìm thấy
là artifact reproduction. Đây là giới hạn xác minh trong workspace, không phải
khẳng định không có bản lưu ở nơi khác.

Ngày khóa là một quyết định. Để tái lập thí nghiệm cần có dữ liệu thực: bản ghi
NVD/CPE raw hoặc normalized có provenance, nội dung advisory đã dùng, URL, thời
gian thu, source update/version nếu có và hash artifact. Giữ cả dữ liệu gốc và
phần đã trích, không chỉ danh sách link. Chỉ đánh dấu snapshot hoàn thành khi có
đường dẫn bộ dữ liệu và manifest; không lấy một lần fetch về sau rồi tự gọi là
nội dung của ngày 11/10 nếu không có căn cứ phiên bản.

## R5 — Công thức metric cần xử lý Unknown rõ ràng

Bộ metric D-026 phù hợp. Đề xuất contract triển khai sau cho **case có nhãn đã
xác định**; Unresolved báo riêng, không nằm trong N:

| Ground truth / prediction | Applicable | Not Applicable | Unknown |
|---|---|---|---|
| Applicable | TP | FN_def | U_A |
| Not Applicable | FP | TN | U_N |

`FN_def` là kết luận âm sai chắc chắn; `U_A` là ca dương bị bỏ lỡ do abstention.
Đề xuất báo hai số riêng để không đồng nhất Unknown với kết luận âm.

```text
N = TP + FP + TN + FN_def + U_A + U_N
precision = TP / (TP + FP)
recall = TP / (TP + FN_def + U_A)
F1 = 2*TP / (2*TP + FP + FN_def + U_A)
coverage = (TP + FP + TN + FN_def) / N
Unknown rate = (U_A + U_N) / N
```

F1 trên tương đương harmonic mean khi precision/recall xác định, và vẫn tính
chi phí bỏ lỡ U_A. Không dùng công thức F1 bỏ U_A hoặc bỏ Unknown trước khi gọi
hàm metric. Trường hợp mẫu số 0 cần quy ước trước: đề xuất N/A cho đại lượng
không xác định; F1=0 khi count-formula có mẫu số dương nhưng TP=0. Không đổi
chính sách sau khi thấy kết quả. Các công thức là operational clarification
đề xuất, không tự nâng các phần chưa ghi của D-026 thành một quyết định mới.

**Kiểm tra số học giả định, không phải kết quả benchmark:** TP=6, FP=1, TN=8,
FN_def=1, U_A=3, U_N=1 → N=20; precision=6/7; recall=6/10; F1=12/17;
coverage=16/20; Unknown rate=4/20. Nếu bỏ U_A, recall bị báo thành 6/7, trái D-026.

## Việc tiếp theo

Giải quyết khác biệt R1 và thứ tự/thiếu dữ liệu R2 bằng một bản sửa được ghi nhận
trước evaluation. Sau đó hoàn thành collector/mapping và artifact snapshot;
khóa version/hash, ghi nhóm development/evaluation và công thức metric. Giữ
baseline trùng lặp như đã công bố, không thêm khác biệt giả để làm đẹp so sánh.

Context còn các dòng nói metrics/rules “chưa chốt” dù D-026 đã ACCEPTED; cần
đồng bộ trạng thái, tách **đã chốt danh sách/ý định khóa** khỏi **artifact và
contract triển khai chưa hoàn thành**. D-011 vẫn PROVISIONAL.

## Đối chiếu sau bản sửa R1/R2/R5 (11/10/2026)

Đã đọc lại fusion-design, phần metric trong protocol và trạng thái D-027/TODO:

- **R1 đã xử lý đúng trong bản nháp:** tầng version không dừng sớm; quy tắc cuối
  dùng B/P_i thống nhất. Khi B chưa rõ nhưng target đúng, phạm vi đủ và mọi đường
  được xác nhận False thì kết luận NA; thiếu phạm vi hoặc chỉ không thấy dấu hiệu
  vẫn chưa đủ cho nhánh này. Không còn yêu cầu B=True ở nhánh config-blocked.
- **R2 đã xử lý đúng:** Advisory-only xét build đã vá trước các nhánh dữ liệu/
  precondition thiếu; quy tắc chung phân biệt thiếu bản ghi/range/product match
  với bằng chứng ngoài dải. Giữ giới hạn nối target với build và nguồn được phép.
- **R5 đã xử lý đúng:** bảng sáu ô tách FN_def khỏi U_A; recall/F1 giữ U_A;
  coverage/Unknown rate có cùng N; mẫu số 0 báo N/A, F1=0 khi TP=0 và mẫu số dương.
- **R3/R4 vẫn pending đúng như khai báo:** TODO có công việc snapshot raw/extracted
  với manifest và collector/mapping freeze cùng development/evaluation grouping.
  Chưa xác minh các artifact/mapping này đã được tạo.

Không phát hiện vấn đề mới cần sửa trong phạm vi follow-up R1/R2/R5. Có thể đi
tiếp sang snapshot và collector/mapping; evaluation cuối chờ các phần đó hoàn
thành và khóa. Đây là xác nhận bản nháp đã xử lý nhận xét, không nâng D-011/D-027
lên ACCEPTED và không xác nhận hiệu năng của một implementation chưa chạy.
