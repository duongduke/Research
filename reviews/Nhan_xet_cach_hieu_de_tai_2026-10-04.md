# Nhận xét cách hiểu đề tài và ý trợ giảng

Ngày: 04/10/2026 (Asia/Saigon). Đây là nhận xét và kiến nghị để thảo luận; không phê duyệt hay thay đổi phương pháp nghiên cứu.

## Phạm vi và căn cứ

Đọc toàn bộ `research/plan-so-bo.tex`, `design/phuong-phap-nghien-cuu.md`, bốn file trạng thái trong `context/`, handoff lịch sử, README và ghi chú hai bài báo. Đối chiếu các đoạn liên quan trong bản trích xuất hai PDF ở `tmp/pdfs/` và advisory Apache chính thức.

Theo giải thích của người dùng: LaTeX là nguồn tạo PDF tìm hiểu sơ bộ để đưa trợ giảng; Markdown trong `design` tổng hợp trao đổi với Gemini. Người dùng cũng có trao đổi với DeepSeek. Những tài liệu này có vai trò khác nhau; bản tổng hợp không tự trở thành xác nhận của trợ giảng.

Không tìm thấy bản xuất toàn bộ hội thoại trong các tài liệu workspace đã kiểm tra; công cụ đọc các chat Codex khác không có trong phiên này. Vì vậy, lời trợ giảng chỉ được đối chiếu qua phần trích/tóm tắt đã lưu, không xác minh được toàn bộ câu chữ hay ngữ cảnh gốc. Sự tồn tại của PDF không chứng minh tài liệu đã được gửi hoặc được duyệt.

## Đánh giá chung

Hai tài liệu mới đưa ra một hướng cụ thể hơn trạng thái ngày 30/09: đánh giá evidence fusion cho CVE applicability, dùng Apache làm đối tượng chính và lab làm bằng chứng hỗ trợ gán nhãn. Khung so sánh trên cùng benchmark, giữ Unknown và tách applicability khỏi thành công khai thác là các điểm hợp lý.

Tuy nhiên, hiện có độ lệch giữa tên bài toán, định nghĩa nhãn và diễn giải hướng 3. Cần giải quyết độ lệch đó trước khi coi thiết kế là phương pháp đã chốt. Trạng thái phù hợp hiện nay là **đề xuất có lý do**, chưa có căn cứ trong workspace cho thấy trợ giảng đã duyệt.

## Phát hiện theo mức độ ảnh hưởng

### 1. Quan trọng nhất: “Applicable” đang chỉ các đối tượng khác nhau

Căn cứ: LaTeX dòng 45 định nghĩa là CVE khớp đúng product/version; Markdown dòng 70 định nghĩa là mã lỗi có mặt trong version; `context/PROJECT.md` mục 3 và 7 phân biệt affected release với applicability trong cấu hình cụ thể.

Định nghĩa mới có thể là một bài toán nghiên cứu hợp lệ, nhưng gần với xác định bản phần mềm bị ảnh hưởng hơn cách hiểu applicability theo triển khai. Không thể dùng ba nghĩa thay nhau rồi chấm chung một metric.

| Câu hỏi cần trả lời | Đơn vị phù hợp | Bằng chứng còn cần làm rõ |
|---|---|---|
| Bản phần mềm này có bị CVE ảnh hưởng không? | Product, release/build, CVE | Danh tính bản phát hành, trạng thái bản vá, logic lỗi |
| CVE có áp dụng cho triển khai cụ thể không? | Deployment, CVE | Bản phần mềm và các tiền điều kiện cấu hình, tính năng, quyền truy cập liên quan |
| Có khai thác thành công trong phép thử không? | Deployment, CVE, phép thử | Kết quả thực thi trong điều kiện đã ghi lại |

Ví dụ trong lab hiện có: cùng Apache 2.4.49 có thể chạy với cấu hình mặc định hoặc cấu hình đã nới quyền. Advisory Apache xác định release 2.4.49 bị ảnh hưởng và nêu quyền truy cập ngoài thư mục Alias là điều kiện để yêu cầu tiết lộ tệp thành công; CGI là điều kiện bổ sung cho thực thi mã. Do đó, khác kết quả yêu cầu không tự thay đổi release bị ảnh hưởng. [Nguồn Apache](https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773).

Nếu chọn đánh giá theo bản phần mềm, cần nói rõ giới hạn kết luận. Nếu chọn applicability theo triển khai, chỉ `(product, version, CVE)` chưa đủ biểu diễn những ca khác cấu hình. Đây là lựa chọn cần thảo luận và ghi quyết định mới trước khi áp dụng; bản review không chọn thay người dùng.

### 2. Quan trọng: diễn giải ý trợ giảng và dấu [CHỐT] vượt bằng chứng hiện có

Căn cứ: Markdown dòng 15 gọi pipeline là “chính thức”, dòng 30 kết luận ba hướng là ba mức sâu của cùng bài toán, dòng 59 và 101 đánh dấu vai trò lab/phương pháp là [CHỐT]. Trong khi đó, `DECISIONS.md` vẫn ghi hướng chính, nhãn và vai trò PoC còn mở; chính Markdown cũng đánh dấu hướng 3 là giả định.

Ba hướng liên quan trong quy trình đánh giá CVE, nhưng có đầu ra riêng: version/range, thứ tự ưu tiên, và kết luận applicability. Gọi chúng là ba mức sâu là một cách diễn giải hữu ích, không đủ căn cứ để khẳng định đó là ý định của trợ giảng hoặc hướng 3 là bắt buộc.

Tương tự, câu “cách cơ bản em hiểu là đúng rồi” không tự chứng minh trợ giảng đánh giá cách hiểu là “còn nông”. Cần giữ phần này dưới nhãn **diễn giải của người viết**. “Hướng 3 gần với câu hỏi gốc nhất theo cách hiểu hiện tại” thận trọng hơn “hướng 3 chính là đề tài gốc”.

### 3. Quan trọng: lab bổ sung bằng chứng, chưa bảo đảm nhãn độc lập cho toàn benchmark

Căn cứ: Markdown dòng 61–63 lấy advisory/patch cho đa số nhãn, lab cho tập con và kết luận không circular vì lab không vào fusion. LaTeX dòng 120 và 122 dùng advisory/patch cả trong nguồn phương pháp lẫn quy trình gán nhãn.

Tách kết quả lab khỏi đầu vào fusion là đúng, nhưng chưa xử lý sự phụ thuộc của nhãn ngoài lab. Hai người gán nhãn độc lập về thao tác vẫn có thể đọc cùng nguồn mà mô hình đang sử dụng. Việc dùng chung tài liệu không tự làm benchmark vô hiệu; cần công khai mức phụ thuộc và cách kiểm chứng vượt việc sao chép một trường dữ liệu.

Một PoC thành công hỗ trợ nhãn dương cho đúng triển khai và điều kiện thử. PoC thất bại không đủ gán nhãn âm: có thể sai yêu cầu, sai tiền điều kiện hoặc phép thử không bao phủ. Không nên gọi cả tập nhãn là “xác nhận cứng”.

Khi viết protocol, cần ghi lý do nhãn từng ca, nguồn đối chiếu, bất đồng và giới hạn kết luận; người gán nhãn không xem dự đoán của phương pháp. Lab có thể thuộc nhánh xây/kiểm tra benchmark, nhưng vai trò này vẫn là đề xuất cần xác nhận, không phải điều đã được trợ giảng chốt.

### 4. Quan trọng: “detected product/version” chưa quy định mức thông tin được phép biết

Căn cứ: pipeline trong cả hai tài liệu bắt đầu bằng product/version; kịch bản nginx Ubuntu dùng backport; D-003 chỉ cho quan sát mục tiêu qua HTTP và giữ SSH/container làm ground truth.

Nếu nghiên cứu bắt đầu sau bước phát hiện, có thể đánh giá riêng khả năng đối chiếu CVE với thông tin đầu vào đã có. Phải nói rõ kết quả là có điều kiện theo chất lượng thông tin đó, chưa chứng minh chất lượng một scanner từ URL đến kết luận.

Nếu tuyên bố kết luận cho website cụ thể, cần ghi product/version hoặc khoảng version thực sự quan sát được. Không được cấp package revision hay trạng thái bản vá từ SSH cho scanner mà vẫn gọi là quan sát từ web. Khi hai bản build khác nhau cho bằng chứng HTTP giống nhau, phương pháp có thể phải giữ Unknown; thêm nhiều nguồn công khai không tự giải được sự thiếu thông tin về bản đang triển khai.

### 5. Mức vừa: hai bài báo đang được dùng để biện minh quá rộng

Căn cứ: LaTeX dòng 97 và 107; ghi chú đọc bài mục 2–3; VAVI bảng III/IX và Vuln2Action phần giới hạn.

VAVI báo công cụ đơn tốt nhất đạt 44,9% accuracy ở mức **đúng toàn bộ tập affected versions**. “Công cụ đơn” không có nghĩa “một nguồn bằng chứng đơn”; con số đó không đo CPE-only và không trực tiếp dự báo baseline của đồ án. Bài có kết quả ensemble hữu ích, nhưng kết hợp công cụ suy luận khác kết hợp các nguồn advisory/CPE/patch.

Vuln2Action không thực thi kiểm chứng các bước sinh là giới hạn có thật. Tuy nhiên, dùng lab gán nhãn cho classifier applicability chưa chứng minh đã lấp khoảng trống kiểm chứng **đầu ra sinh của Vuln2Action**. Liên hệ phù hợp hiện nay là học cách nối các nguồn tri thức và rút kinh nghiệm về giới hạn đánh giá bằng văn bản. Cần khảo sát thêm trước khi khẳng định tính mới.

### 6. Mức vừa: thiết kế đánh giá còn thiếu các quy ước quyết định

Căn cứ: Markdown mục 4, LaTeX mục 6. Đây là các điểm phải hoàn thiện nếu chọn hướng fusion, chưa phải thay đổi phương pháp đã áp dụng.

- **Unknown:** phân biệt nhãn tham chiếu chưa xác định với việc phương pháp từ chối kết luận trên một ca đã có nhãn. Cần báo tỷ lệ kết luận/Unknown cùng độ đúng; không chỉ chấm các ca dễ mà phương pháp chọn trả lời.
- **False mapping:** quy định rõ là ghép nhầm sản phẩm, nhầm bản phát hành hay kết luận dương sai; phải có mẫu số để tính tỷ lệ.
- **Giá trị của fusion:** thắng CPE-only chưa đủ cho thấy kết hợp tốt hơn nguồn đơn mạnh nhất. Cần cân nhắc đối chiếu vendor-only và bỏ từng nguồn để biết lợi ích đến từ đâu; chi phí cũng nên được ghi nhận.
- **Quan hệ giữa nguồn:** CPE/NVD, advisory, history và patch reference có thể phản ánh cùng một thông tin gốc. Không nên coi mỗi URL là một phiếu xác nhận độc lập; cần truy nguồn và xử lý xung đột.
- **Chọn ca:** câu “nginx ... nơi fusion thắng rõ” ở Markdown dòng 88 là kỳ vọng chưa đo. Cần chọn cả ca nguồn nhất quán, mâu thuẫn, thiếu dữ liệu, bản đã vá và chưa vá theo tiêu chí định trước.
- **Chia dữ liệu:** nếu chỉnh luật/trọng số trên một tập rồi chấm chính tập ấy, kết quả dễ thiên lệch. Cần tách phần phát triển và đánh giá; các version cùng CVE có quan hệ chặt nên cân nhắc chia theo CVE/nhóm ca và báo mức bao phủ.
- **Người gán nhãn:** “hai người + phân xử” là protocol học từ VAVI, chưa có bằng chứng đã có nhân lực thực hiện. Cần xác định cách làm khả thi trước khi cam kết trong kế hoạch.

### 7. Mức nhẹ: phần định nghĩa web interface và nguồn dẫn cần gọn, chính xác hơn

Căn cứ: LaTeX mục 3 và tài liệu tham khảo; Markdown mục 7.

Việc gọi bốn nhóm là phạm vi operational do người viết chọn là đúng. Định nghĩa “System” rộng của OWASP không chứng minh duy nhất cách chia này, và “publicly exposed” nói về khả năng tiếp cận, không định nghĩa toàn bộ đối tượng web-facing. [Glossary OWASP](https://owasp.github.io/www-project-secure-coding-practices-quick-reference-guide/stable-en/03-appendices/05-glossary).

Ngoài phạm vi nên được diễn đạt là lựa chọn giới hạn đồ án; lập luận một nhóm bị loại vì tất cả thành phần nhóm ấy “không nói HTTP” quá tuyệt đối. Không cần mở rộng scope để sửa cách viết.

Đã mở nguồn NIST và OWASP trong lần review. Hai URL CISA được dẫn trả lỗi qua công cụ web; tìm kiếm tiêu đề BOD 26-04 được ghi trong LaTeX không trả kết quả. Chưa xác minh được dẫn nguồn này, cũng chưa có căn cứ kết luận nó không tồn tại. Cần kiểm tra lại mã, tiêu đề, câu trích và URL trước khi sử dụng trong bản gửi. Hai bài báo đã được đối chiếu với nội dung lưu tại workspace.

## Cách diễn đạt khi trao đổi với trợ giảng

Có thể trình bày theo mạch: “Em hiểu câu hỏi gốc là kiểm tra một CVE có thực sự ảnh hưởng đến product/version đã phát hiện bằng nhiều nguồn bằng chứng. Em đề xuất đánh giá fusion so với baseline trên cùng benchmark, với lab hỗ trợ kiểm chứng một tập con. Em cần thống nhất chữ ‘áp dụng/khả thi’ đang chỉ bản phần mềm bị ảnh hưởng hay triển khai thỏa tiền điều kiện, vì hai mức này cần nhãn và đầu vào khác nhau.”

Ba điểm cần xác nhận trước là: đơn vị và nghĩa nhãn; thông tin nào có sẵn cho phương pháp; và vai trò lab/ranh giới không khai thác. Sau đó mới cố định baseline, dataset và metric.

## Trạng thái sau review

Chưa sửa LaTeX, PDF hay Markdown tổng hợp. Chưa thay quyết định D-001–D-006, chưa phê duyệt hướng 3 hoặc protocol nhãn. Chưa chạy lab hay thí nghiệm mới. Các phát hiện trên là kiến nghị; mọi thay đổi phương pháp được áp dụng sau này cần một entry mới trong `context/DECISIONS.md` theo AGENTS.md.
