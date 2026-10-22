# Bước 2 mapping: có thể bắt đầu rà, chưa khóa — 14/10/2026

Phạm vi: kiểm tra sơ bộ bảng `notes/collector-mapping-30cve.md`, các điểm mở,
spec D-028, rule/protocol và một số trường snapshot 5631/1001000. Chưa audit đủ
60 probe hoặc mọi source/artifact ref; không chạy lab, sửa mapping, đổi nhãn
hay freeze. Đề xuất xử lý ghi ở **D-029 PROVISIONAL**.

## Khuyến nghị

Cho researcher bắt đầu bước 2 ngay: rà nội dung, lập bảng phán quyết và sửa
mapping theo căn cứ. Tách kết quả review khỏi hành động khóa version/hash. Số
pending cao không cản việc rà, và không cần nâng tất cả lên verified cho đẹp;
phần chưa đủ bằng chứng có thể giữ Unknown với chính sách thực thi được ghi rõ.

## Các lỗi đã nhìn thấy ngoài danh sách phán quyết

1. **Config-off đang được OR như đường gây tác động.** Các section 12640/12641/
   13671 có `path_config_off` chứa `NOT(p_installer_public)` hoặc phủ định feature
   bắt buộc. Nếu B=True và feature=False, nhánh này có thể thành P_i=True và sinh
   Applicable. Canonical rule chỉ OR các đường tạo tác động; thiếu feature là căn
   cứ chặn đường đó, không phải một đường tác động dương thay thế. Cần sửa trước
   freeze, giữ nguyên nhãn chuẩn.
2. **403/404 đơn lẻ thành False.** Nhiều `false_when` dùng 403/404 hoặc không thấy
   login/feature làm bằng chứng vắng; trái nguyên tắc Unknown khi route/auth/proxy
   còn nhập nhằng. Pending không chữa được logic nếu implementation sau này vẫn
   áp các nhánh False này. Cần kiểm đúng predicate và access model.
3. **5631 tách injection và execution thành hai đường thay thế.** File gọi
   server-side SVG injection một P_i riêng, còn browser execution là một P_i khác.
   Với mục tiêu XSS và chuẩn D-015/D-024, bypass sanitizer là một bước của chuỗi,
   chưa tự là đường hoàn chỉnh thay thế việc thực thi script. Không đổi mục tiêu
   sang primitive-level để né điều kiện; giữ hai nhãn XSS Unresolved đã chốt.
4. **E5 còn bị gộp với affected-range matching.** Nhiều probe version `maps_to`
   predicate như `p_core_version_affected`/`p_version_lt_*`, với cutoff viết sẵn.
   Kiểm tra khi điền/triển khai để giữ observed version riêng và dùng dải được
   phép cho từng method, tránh truyền quyết định theo advisory cho CPE-only.
   NVD-only trong rule đã ghi dùng CPE của NVD; không âm thầm thay thành CNA
   `affectedData` để tạo một baseline khác. Nếu muốn thay đổi, cần amendment.

Đây là findings sơ bộ; không đồng nghĩa phần còn lại của 2.408 dòng đã được
chứng nhận đúng. Các probe POST mới cũng cần được rà phương thức/body, khả năng
thay đổi trạng thái và ranh giới quan sát không khai thác theo contract.

## Hướng xử lý sáu điểm người dùng nêu

| Điểm | Việc researcher làm trong bước 2 |
|---|---|
| nginx một trạng thái | Tách xác nhận chuỗi header E5 khỏi khả năng phân biệt build vá/unpatched E4. Giữ giới hạn coverage; hiện definition verified cần đủ control nên không tự miễn đối chứng. Muốn đổi nghĩa validation phải ghi quyết định trước freeze. |
| Capture trong file reproduction | Rà exact request/response, access và fixture có bị PoC làm thay đổi không. Tên file không đủ chứng minh một probe hợp lệ; giữ pending khi bằng chứng không đáp ứng contract. Mọi ngoại lệ dùng lại capture phải có lý do/trace và quyết định phù hợp, không chấp nhận cả nhóm một lần. |
| 5631 range conflict | Giữ các assertion và scope của từng nguồn. Snapshot có cả description khớp CPE lẫn `affectedData` khác boundary; là khác biệt nội dung thực cần ghi provenance. Áp precedence đã chốt khi cùng phạm vi, Unknown khi chưa giải được; không sửa raw snapshot theo ground truth. |
| Advisory range thiếu | Đọc nội dung vendor/fallback thực tế và trích đoạn đủ căn cứ; không đồng nhất không machine-readable với không có thông tin. Nếu thực sự thiếu thì giữ Unknown cho assertion cần nó; giữ nhánh bản vá độc lập khi đủ căn cứ. Không vay CPE/NVD rồi gọi là advisory-only. |
| CPE exact và 4.7.2 | Giữ nguyên snapshot. CPE-only theo dữ liệu nguồn có thể trả dương trên bản GT âm; đó là false mapping để đo. Fusion áp luật và bằng chứng vendor đúng scope, không hardcode ngoại lệ từ đáp án. Rà cả exact-version và range operators. |
| Development flags | Dựa trên việc ca có thật sự dùng chọn/tinh chỉnh rule/signal và artifact chứng minh. Không hạ cờ để tăng nhóm evaluation. Nếu chưa đủ lịch sử thì ghi uncertain/reason và báo mức exposure, không mặc định held-out sạch. |

## Điều kiện kết thúc bước 2

- Bảng phán quyết có căn cứ cho các điểm mở và các findings trên; source fields,
  condition/path IDs và artifact references đã kiểm tra.
- Mapping tuân thủ canonical rule, input của từng phương pháp và contract probe.
- Trạng thái validation/coverage được ghi đúng. Quy định runtime cho probe chưa
  kiểm chứng/không quan sát được, giữ Unknown khi chưa đủ căn cứ; không buộc mọi
  precondition phải có dấu hiệu HTTP hoặc loại case chỉ vì method khó kết luận.
- Ghi development use; khóa đúng nội dung đã rà bằng version/hash trước evaluation.

Có thể tiến hành review trên artifact hiện có ngay. Request quan sát/lab bổ sung
là một công việc riêng theo scope đã cho phép; lượt kiểm tra này không chạy chúng.
Một hash của file DRAFT chưa giải mâu thuẫn không thay thế việc review.
