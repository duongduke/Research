# Review định nghĩa nhãn chuẩn và dự đoán — 11/10/2026

Phạm vi: bảng định nghĩa người dùng đưa trong chat; đối chiếu protocol, fusion
design, D-010/D-011/D-015/D-019–D-024 và artifact của Apache, nginx, Roundcube
CVE-2020-12640. Không chạy lab mới hoặc xác minh lại toàn bộ benchmark.

Trạng thái: nhận xét và đề xuất làm rõ ở **D-025 PROVISIONAL**; không sửa nhãn,
artifact hoặc quyết định ACCEPTED. “Bảo vệ được” ở đây nghĩa là có thể giải thích
định nghĩa và căn cứ kiểm chứng; không xác nhận mọi nhãn đã được audit độc lập.

## Kết luận

Phần lõi có thể bảo vệ: nhãn chuẩn tách khỏi dự đoán; Unresolved tách Unknown;
Applicable cần bằng chứng thực thi cho nhãn chuẩn nhưng phương pháp được dự đoán
từ bằng chứng không khai thác; Not Applicable có hai nhánh; PoC thất bại không tự
sinh nhãn âm. Các luật B/P_i hợp lý khi predicate và phạm vi đường tác động đã
được xác định. Cần làm rõ các điểm dưới đây khi trình bày.

## R1 — Build affected khác upstream version thuộc dải

Viết nhánh âm (a): **build đã xác minh không bị ảnh hưởng hoặc đã chứa bản vá**.
Phiên bản ngoài dải đáng tin là một cách xác lập nhánh này, không phải điều kiện
bắt buộc cho mọi bản vá. Backport có thể giữ upstream version trong dải affected.

Đề xuất định nghĩa nhãn dương: build thuộc phạm vi ảnh hưởng, case/version/config/
access model đã xác định, và reproduction chứng minh tác động của đúng CVE trên
case đó. Không lấy một marker được tạo bằng hành động khác làm bằng chứng CVE.

## R2 — Bằng chứng tác động không đồng nghĩa mọi bằng chứng phải ngoài HTTP

D-015 nhấn mạnh hiệu ứng thực thi thay vì mã trạng thái. Protocol hiện viết thêm
“bằng chứng phải được kiểm ngoài băng tần (ngoài phản hồi HTTP)”, trong khi file
disclosure có thể chứng minh qua nội dung HTTP chứa marker riêng của file ngoài
document root, đối chiếu fixture/logs. Artifact Apache 2021-41773 là ví dụ có sẵn.

Đề xuất câu tổng quát: **Reproduction thành công khi quan sát và kiểm chứng được
tác động thực sự của CVE; không suy từ mã HTTP. Loại bằng chứng tác động được quy
định theo CVE, có artifact và đối chứng.** Marker được kiểm trong filesystem,
browser execution hoặc callback là các cách xác minh phù hợp tùy loại tác động;
nội dung file thu qua HTTP cũng có thể là bằng chứng trực tiếp với đối chiếu đủ.

Đây là đề xuất làm rõ wording của D-015/protocol, chưa tự thay yêu cầu ACCEPTED.
Đối với XSS, HTML/payload hiện trong response vẫn chưa thay thế việc thực thi
script theo chuẩn đang dùng; hai ca pending của D-024 giữ nguyên Unresolved.

## R3 — “Bật installer → Applicable” bỏ sót tiền điều kiện và loại reproduction

README và artifact CVE-2020-12640 ghi rõ control dương đã đặt sẵn `plugins` chứa
traversal và file PHP trong filesystem. Nó chứng minh tác động của loader trong
case có fixture đó và khác biệt với bản fixed. Chưa đủ để nói artifact đã tái
tạo toàn bộ chuỗi một attacker chỉ có quyền HTTP tự đi qua installer, ghi config
và đặt file. Việc mô phỏng phải được mô tả đúng với phạm vi claim.

Tài liệu của tác giả PoC yêu cầu **access installer và write access filesystem**;
patch vendor kiểm tra tên plugin để chặn traversal. Vì vậy câu ví dụ cần thành:
“Bản affected + điều kiện installer/config và quyền ghi file đã xác định trong
case + reproduction cho thấy include/thực thi → Applicable trong phạm vi case.”
[Tác giả PoC](https://github.com/mbadanoiu/CVE-2020-12640),
[patch Roundcube](https://github.com/roundcube/roundcubemail/commit/219e353a).

Nhánh âm default được ghi ACCEPTED ở D-022/D-023. Khi bảo vệ, trình bằng chứng
nội bộ rằng installer thật sự không có và liệt kê đường tác động/access model
đang xét. Không dùng riêng HTTP 404 để suy ra absence; không nói thiếu installer
chặn mọi cách một actor với quyền ghi config/filesystem có thể thay đổi `plugins`.
Review không tự thay nhãn đã được chấp nhận.

## R4 — Giới hạn câu “Unknown không phải sai” và phạm vi nhãn âm

Viết: **Unknown là từ chối kết luận, không phải một kết luận nhị phân sai chắc
chắn; nó vẫn giảm coverage và làm bỏ lỡ ca dương trong recall tổng thể.** Một
phương pháp luôn Unknown không có giá trị phát hiện dù không có false positive.

Unknown là loại đầu ra của phương pháp, không phụ thuộc việc case đã có ground
truth hay chưa. Metrics có đối chiếu đúng/sai chỉ dùng ca có nhãn đã xác định;
Unresolved phải báo số lượng và lý do riêng. Precision/recall/coverage/Unknown
rate cho nhóm resolved phải ghi rõ mẫu số, tránh loại ca khó mà không báo cáo.

“Mọi đường” luôn là mọi đường liên quan **trong phạm vi CVE, phiên bản, cấu hình,
actor/access model đã xác định**, không phải khẳng định không tồn tại bất kỳ cách
tấn công nào. Khi phạm vi đường chưa đủ hoặc điều kiện chưa xác minh, không đóng
nhãn âm hoặc prediction âm từ sự im lặng của phép quan sát.

## R5 — nginx là nhãn âm kiểm chứng bản vá, không phải CVE đã reproduce dương

README nginx ghi **no exploitation attempted**; bằng chứng gồm container/package
identity và đối chiếu bản vá. Tracker Ubuntu ghi jammy Fixed 1.18.0-6ubuntu9;
artifact lab ghi package 1.18.0-6ubuntu14.21. Nhãn âm này được chấp nhận riêng ở
D-020. [Ubuntu tracker](https://ubuntu.com/security/CVE-2021-23017).

Câu “người gán nhãn dùng advisory + reproduce” cần giải thích loại bằng chứng
của từng nhánh. Không trình ca nginx như một reproduction dương đã thành công.
D-010 có wording “no reproduction → no ground truth”, trong khi D-020 chấp nhận
đối chứng bản vá không khai thác: cần làm rõ phạm vi áp dụng trong protocol và
trong thống kê. Review không sửa D-010 hoặc hủy D-020.

Artifact header thiếu revision minh họa được vì sao build identity có trong
ground truth nhưng chưa có qua HTTP. Unknown ở đây là dự đoán **theo luật đề
xuất và bằng chứng hiện có**, chưa phải output của một chương trình fusion đã
được triển khai/chạy trên benchmark.

## Cách trình bày khi được hỏi về cơ sở nhãn

“Em gán nhãn cho từng triển khai cụ thể, trong phạm vi actor và đường tác động
đã mô tả. Nhãn dương cần bằng chứng tác động thực thi. Nhãn âm cần bằng chứng
build không affected/đã vá, hoặc mỗi đường liên quan thiếu một điều kiện bắt buộc
đã kiểm chứng. Ca chưa đủ căn cứ giữ Unresolved. Mỗi nhãn có tài liệu, manifest
và artifact truy vết; nhãn được lập mà không dùng dự đoán của phương pháp.”

Bảng định nghĩa giải thích cách chấm; manifest, điều kiện, controls và artifact
mới là căn cứ bảo vệ từng nhãn. Các clarifications trên vẫn là đề xuất.
