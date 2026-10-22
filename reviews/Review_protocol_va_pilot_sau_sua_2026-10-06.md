# Nhận xét protocol và pilot sau bản sửa — 06/10/2026

Phạm vi: bản mới của `notes/ground-truth-protocol.md`, `notes/cve-selection-va-lab-ke-hoach-2026-10-06.md`, `notes/pilot-plan-2026-10-06.md`; đối chiếu `context` và review trước. Đây là nhận xét thiết kế, không có lab run hoặc xác minh release mới.

## Kết luận

Bản sửa đã xử lý đúng phần lớn vấn đề trước: tách thông tin HTTP khỏi config ground truth, phân biệt Unresolved và dự đoán Unknown, đếm CVE khác case, sửa loại CVE Roundcube và xây pilot để kiểm tra cả tái tạo lẫn khả năng quan sát. Hướng D-007/D-008 giữ nguyên. Công việc ưu tiên là hoàn thiện thiết kế pilot và quy tắc nhãn/metric; chưa cần mở lại lựa chọn hướng nghiên cứu.

## Phát hiện cần xử lý

### 1. P1 — Sửa logic nhãn âm; diễn đạt review trước của tôi cũng chưa chính xác

Căn cứ: protocol dòng 68–79; selection note dòng 108.

“Cả hai: ngoài dải đáng tin và vắng tất cả tiền điều kiện” đang không khớp với bảng luật. Có hai nhánh nhãn âm: (a) xác minh bản không bị ảnh hưởng/đã vá; (b) bản bị ảnh hưởng nhưng mọi đường tác động trong phạm vi đều bị loại trừ bởi tiền điều kiện cần thiết vắng. Nhánh (a) không cần thêm điều kiện cấu hình tắt.

Trong nhánh (b), không cần mọi tiền điều kiện đều vắng. Nếu một đường đòi A **và** B thì vắng A đã loại đường đó; nếu còn đường thay thế C thì phải kiểm tra cả C. Diễn đạt đúng là **mỗi đường liên quan đều thiếu ít nhất một điều kiện bắt buộc**, với phạm vi đường tác động được xác định và căn cứ kiểm chứng đủ. Phiên bản, tác động, actor/access model và cách kiểm chứng cần được ghi rõ.

Cách nói “vắng mọi tiền điều kiện” trong review trước của tôi quá mạnh và đã được bản sửa lặp lại. Đây là điểm cần sửa từ lời khuyên trước, không phải lỗi riêng của người soạn protocol.

### 2. P1 — Hàng Roundcube chưa tách rõ quan sát của phương pháp và fixture PoC

Căn cứ: pilot dòng 18, 54–62.

Pilot nói unauthenticated là chính, nhưng Roundcube dự kiến fetch email cần auth. Cần quy định rõ trường hợp này: tài khoản bình thường được cấp cho scanner, hay chỉ người kiểm chứng ground truth có tài khoản. Hai access model không được gộp trong kết luận.

“Payload hiện trong HTML email” chưa đủ chứng minh CVE applicable. Payload do nhóm tự đặt cho reproduction, và thực thi trình duyệt là bằng chứng ground truth. Nếu cấp luôn thông tin fixture này cho fusion, có nguy cơ phương pháp đang nhận dữ liệu từ quá trình kiểm chứng thay vì quan sát độc lập.

Kiến nghị: ghi riêng dấu hiệu HTTP có thể thu mà không kích hoạt lỗi và fixture/bằng chứng thực thi của reproduction. Thu đầu vào phương pháp trước PoC hoặc trên bản reset tương đương; không vô tình sử dụng trạng thái tài khoản/inbox/cookie đã thay đổi sau PoC. Có thể pilot cho thấy không đủ dấu hiệu trong access model đã chọn; đó là kết quả về observability cần ghi nhận.

### 3. P2 — Unknown không tự là kết luận sai, nhưng có chi phí đánh giá

Căn cứ: protocol dòng 88–97.

Tách nhãn chuẩn và dự đoán là đúng. Tuy nhiên, gọi Unknown trên một positive là “sai sót” cần giới hạn nghĩa: đó có thể là bỏ lỡ positive trong đánh giá hiệu quả tổng thể, nhưng vẫn là từ chối kết luận đúng đắn khi bằng chứng thiếu. Không nên thưởng đoán chắc thiếu căn cứ để tăng coverage.

Kiến nghị PROPOSED cho ca ground truth đã xác định:

- Coverage = số dự đoán Applicable hoặc Not Applicable / số ca có nhãn chuẩn đã xác định.
- Unknown rate dùng cùng mẫu số; khi mọi ca đều có dự đoán thì bằng 1 − coverage.
- Precision của Applicable dựa trên các dự đoán Applicable.
- Recall tổng thể của Applicable giữ **toàn bộ** ground-truth Applicable trong mẫu số, kể cả dự đoán Unknown; không âm thầm bỏ Unknown rồi báo recall cao hơn.
- Nếu báo độ đúng chỉ trên các ca phương pháp kết luận, ghi rõ đó là metric có điều kiện và trình cùng coverage; phải tách dự đoán sai chắc chắn với abstention.

Quy ước cuối vẫn cần chốt. Không có giá trị metric thực nghiệm trong nhận xét này.

### 4. P2 — Unresolved là tình trạng chưa có nhãn, không cần hạn ngạch như một lớp mục tiêu

Căn cứ: selection note dòng 45–46.

Đã đổi Unknown thành Unresolved nhưng còn yêu cầu “đủ cả Applicable, Not Applicable, Unresolved”. Theo protocol mới, Unresolved là bucket chưa giải quyết và không chấm precision/recall. Không nên chủ động chọn các ca không chấm được chỉ để đủ lớp.

Cần có ca nhãn dương và âm kiểm chứng được; có thể thêm điều kiện quan sát hạn chế để đo Unknown của phương pháp. Những ca nhãn chưa giải quyết được phải lưu và báo tỷ lệ/lý do, không xóa để làm kết quả đẹp. Quan sát hạn chế vẫn có thể áp dụng cho ca ground truth đã xác định.

### 5. P2 — Pilot cần đặc tả đủ để chạy và diễn giải, dù có thể thu kết quả không thành công

Căn cứ: pilot mục ngân sách quan sát, ca A–C và tiêu chí thành công.

Hiện version “9.0.x”, “8.6.x” và “Roundcube version lỗi” vẫn là nhóm release; chưa có build cụ thể, dependency/fixture cố định và bản fixed đối chứng. Ca A còn thiếu đối chứng 2FA tắt; ca B cần tách các trạng thái web-services cùng fixture; ca C cần reset mailbox/browser và phiên bản fixed phù hợp. Số lần chạy, giới hạn request, tài khoản, cách xác minh dấu hiệu và lý do dừng cần được định nghĩa trước khi thực hiện.

“GET/HEAD + probe tối thiểu” chưa phải ngân sách quan sát đo được. Ghi danh sách/giới hạn request, số lần thử và access model để tránh khảo sát thêm tùy ý sau khi đã thấy kết quả.

Không chỉ coi pilot thành công khi cả ba CVE reproduce được và có dấu hiệu HTTP. Pilot còn có ích khi phát hiện ca không dựng được hoặc tiền điều kiện không quan sát được dưới budget. Phân biệt **hoàn thành đánh giá khả thi** với **đủ điều kiện đưa CVE vào benchmark**; ghi thất bại có nguyên nhân thay vì chọn lại cho đến khi mọi ca đều thuận lợi.

### 6. P2 — Các trạng thái tài liệu cần đồng bộ, chưa tự nâng thành ACCEPTED

Căn cứ: CURRENT_STATE mục 14, D-012 effect, TODO research P0 và PROJECT.

CURRENT_STATE đã ghi protocol draft áp dụng R1–R4, nhưng D-012 vẫn ghi chưa có đề nghị nào được áp dụng và TODO vẫn nói chưa adopted. Cần phân biệt **đã sửa bản nháp** với **đã phê duyệt protocol**. Có thể cập nhật trạng thái draft mà vẫn giữ D-011/D-012 PROVISIONAL.

PROJECT và câu hỏi trợ giảng vẫn mang trạng thái cũ; không lấy chúng để mở lại D-007–D-010. Các câu “lấp đúng khoảng trống Vuln2Action” và “kịch bản fusion thắng” vẫn cần sửa theo review trước; chưa có thí nghiệm hoặc khảo sát bổ sung chứng minh các khẳng định đó.

## Ưu tiên

Sửa logic nhãn âm, tách quan sát/PoC và xác định access model của ba ca trước. Sau đó chốt release/fixture/control và bảng metric. Bản này ghi kiến nghị ở D-013 PROVISIONAL, chưa sửa các notes hoặc phê duyệt protocol.

## Đối chiếu sau khi người dùng áp dụng D-013 vào bản nháp

Đã đọc lại ba notes và context sau thông báo của người dùng. Protocol đã sửa hai nhánh
nhãn âm, vai trò Unresolved và metric abstention; pilot đã bổ sung release ứng viên,
fixed controls, config/access model, reset và giới hạn 20 request. Đây là thay đổi bản
nháp, không phải phê duyệt hoặc kết quả thực nghiệm.

Đã sửa các chỗ sót đồng bộ theo cùng D-013: summary nhãn âm ở selection note; hàng
Roundcube còn dùng payload làm dấu hiệu (đổi sang quan sát HTML lành tính, không tự
chứng minh XSS); và wording D-012/D-013 còn nói chưa áp dụng. Giữ nguyên PROVISIONAL.

Phần việc tiếp theo thuộc đặc tả thực thi: xác minh artifact/checksum và dependency;
thay path placeholder bằng danh sách request chính xác rồi cố định trước quan sát
đánh giá. Không coi các path có dấu `...` là danh sách đã đóng. Không thực thi pilot
hoặc thay kết luận nghiên cứu trong lượt đối chiếu này.
