# Đọc hai bài liên quan RQ-C1

Ngày: 30/09/2026. Nguồn: hai PDF trong `paper/`. Số trang dưới đây là thứ tự trang trong PDF, không phải số trang proceedings.

## 1. Bài toán hiện tại và điều cần phân biệt

Scope được trợ giảng xác nhận là web interface/web-facing target. Không được hiểu thành chỉ xây giao diện web cho một scanner inventory Ubuntu. Đồng thời, chưa mặc định chỉ làm web server: ứng dụng, framework, plugin hoặc thành phần phục vụ HTTP đều có thể là mục tiêu, tùy đề tài được chốt.

Có ba bài toán khác nhau:

1. Website đang chạy sản phẩm nào, phiên bản/khoảng phiên bản nào? Đây là nhận diện từ bên ngoài.
2. Những phiên bản nào của sản phẩm đó bị một CVE ảnh hưởng? Đây là xác định dải ảnh hưởng từ dữ liệu và bằng chứng.
3. CVE có áp dụng/khai thác được trong cấu hình triển khai cụ thể này không? Phiên bản thuộc dải chưa đủ trả lời mọi điều kiện.

Bài thứ nhất chủ yếu xử lý (2) bằng mã nguồn. Bài thứ hai hỗ trợ diễn giải và dựng giả thuyết reproduction liên quan (3), nhưng không kiểm chứng bằng thực thi. Hai bài không cung cấp sẵn một giải pháp hoàn chỉnh cho nhận diện web từ xa.

## 2. Vulnerability-Affected Versions Identification: How Far Are We?

ASE 2025, Xingchu Chen và cộng sự. File: `paper/Vulnerability-Affected_Versions_Identification.pdf`. Đối chiếu thêm bản tác giả: https://arxiv.org/abs/2509.03876.

### Câu hỏi, đầu vào và đầu ra

Với một lỗ hổng và lịch sử phát hành của dự án, xác định tập phiên bản còn chứa logic dễ bị tổn thương. Đầu vào có mã nguồn, lịch sử Git, commit vá và các phiên bản phát hành; đầu ra là tập phiên bản bị ảnh hưởng. Không phải đưa URL vào rồi suy ra phiên bản bằng HTTP fingerprint.

Hai nhóm phương pháp (trang 2-3):

- Tracing-based: truy ngược từ bản vá để tìm commit đưa lỗi vào, rồi liên hệ lịch sử với phiên bản phát hành; nhiều công cụ dựa trên biến thể SZZ.
- Matching-based: lấy dấu hiệu mã dễ bị tổn thương/bản vá, tìm trong mã nguồn của các phiên bản để phân loại.

### Thiết kế đánh giá và kết quả

12 công cụ, gồm 6 tracing và 6 matching; benchmark 1.128 CVE C/C++ trên 9 dự án, 132 loại CWE (trang 3-5). Có Apache HTTP Server nhưng dataset không chỉ gồm web.

Nhãn chuẩn được xây từ tài liệu chính thức, fixing commits và phân tích mã. Hai người gán nhãn độc lập, người thứ ba giải quyết bất đồng; không đơn thuần lấy kết quả của scanner cần đánh giá làm nhãn chuẩn.

Phải tách hai mức chấm (trang 4-5):

| Mức | Ý nghĩa | Kết quả đáng chú ý |
|---|---|---|
| Toàn bộ tập phiên bản của một CVE | Chỉ đúng nếu không thiếu và không thừa phiên bản | VCCFinder tốt nhất trong công cụ đơn: 44,9% accuracy |
| Từng phiên bản | Tính precision, recall, F1 của các nhãn affected | VCCFinder: 77,8% F1 |
| Ensemble voting | Kết hợp nhiều công cụ | 55,0% accuracy cấp CVE; 84,8% F1 cấp phiên bản |

Ensemble tăng 10,1 **điểm phần trăm** accuracy so với 44,9%, không được diễn giải thành tất cả scanner web chỉ chính xác dưới 45% (trang 11).

### Vì sao vẫn sai, và giới hạn

Bản vá có thể chứa chỉnh sửa không liên quan, chỉ thêm mã, sửa nhiều file/nhánh, hoặc thay đổi điều kiện và luồng điều khiển. Giống một đoạn mã không đủ bảo đảm logic lỗi vẫn tồn tại. Truy đúng một commit cũng chưa đủ bảo đảm suy ra đúng tất cả tag phát hành (trang 5-11).

Kết quả giới hạn ở các dự án mã nguồn mở C/C++; không được chuyển trực tiếp các con số sang PHP/JavaScript hay quét web black-box. Ground truth có phân tích thủ công, vẫn có nguy cơ sai nhãn (trang 11-12).

Lưu ý khi trích số liệu: tổng affected versions trong bảng II là 59.187, khác con số 59.983 trong đoạn văn. Không sử dụng tổng này như một số đã thống nhất nếu chưa đối chiếu artifact/đính chính.

### Điều có thể dùng cho đồ án

- Tách chất lượng nhận diện phiên bản của website khỏi chất lượng dữ liệu dải CVE.
- Có nhãn chuẩn độc lập: phiên bản/config thật trong lab cùng advisory chính thức; nếu cần, thêm bằng chứng mã nguồn hoặc kiểm chứng có kiểm soát.
- Khi ẩn version, cho phép trả khoảng phiên bản/không đủ bằng chứng; không ép đoán một version cụ thể.
- Đo false positive/false negative trên từng website-CVE hoặc phiên bản; nếu đầu ra là toàn bộ tập thì báo thêm exact-set accuracy.

Không cần tái hiện cả 12 công cụ mới có một thí nghiệm web ban đầu.

## 3. Vuln2Action

Tên đầy đủ: Vuln2Action: An LLM-based framework for generating vulnerability reproduction steps and mapping exploits. Shalini Kumari, Geeta Yadav. Journal of Information Security and Applications 99 (2026), 104420. DOI: https://doi.org/10.1016/j.jisa.2026.104420. File: `paper/Vuln2Action.pdf`.

### Mục tiêu và pipeline

Biến mô tả lỗ hổng và tri thức bảo mật thành các bước reproduction dạng văn bản, rồi liên hệ với mô tả/mã exploit. Bài đề cập CVE/CWE/CPE/CAPEC/Exploit-DB; luồng chính nối CVE với CWE, các CAPEC ứng viên và Exploit-DB (trang 4-9).

- Dùng biểu diễn văn bản và cosine similarity để chọn CAPEC liên quan; có so sánh Word2Vec và TF-IDF.
- Fine-tune T5 để sinh luồng Explore/Experiment/Exploit.
- Bổ sung các bước từ mô tả Exploit-DB và tiếp tục huấn luyện.
- Dùng SBERT liên hệ bước sinh với đoạn mã exploit.

GUI của bài dùng Flask và frontend web. **Đó là giao diện của công cụ**, không có nghĩa đối tượng đánh giá của bài chỉ là website. Không đồng nhất GUI này với scope web interface mà trợ giảng giao.

### Bài thật sự đánh giá gì?

| Đánh giá | Số liệu | Không được hiểu thành |
|---|---|---|
| Văn bản sinh so với văn bản tham chiếu | T5 BLEU 0,7589, cùng ROUGE ở bảng 5 | 75,89% PoC chạy thành công |
| CAPEC chọn có thuộc mapping tham chiếu | 89/100 CVE | 89% website được xác nhận có lỗ hổng |
| 3 chuyên gia xem các bước của 20 CVE | Correctness trung bình 86,9%; completeness 4,3/5; clarity 4,4/5 | 86,9% khai thác thành công |

Trang 9 nói kiểm chứng bằng chạy trong sandbox nằm ngoài phạm vi. Trang 12, mục giới hạn, xác nhận luồng sinh ra là mô tả thủ tục, chưa phải exploit thực thi hoặc đã được kiểm chứng; BLEU không bảo đảm đúng ngữ nghĩa hay khai thác thành công trên hệ thống thật.

### Giới hạn cần lưu ý

- Tương đồng văn bản không xác nhận đúng sản phẩm, phiên bản, cấu hình hay điều kiện tiên quyết.
- Cần kiểm tra nguồn và metadata trước khi dùng exploit tương tự làm bằng chứng.
- Bảng 4 ghi BLEU TF-IDF 0,75 và Word2Vec 0,72; một số diễn giải sau đó lại nêu Word2Vec đạt cao nhất khoảng 0,75. Khi báo cáo phải phân biệt bảng/thí nghiệm, không gom mọi số thành một accuracy.
- Dữ liệu được ghi là cung cấp theo yêu cầu; chưa có bộ artifact hoàn chỉnh trong workspace để tái lập toàn bộ kết quả.
- Bài dùng A100 cho thí nghiệm mô hình; điều đó không có nghĩa cần GPU để dựng máy đích web cho đồ án.

### Điều có thể dùng cho đồ án

Học cách kết hợp tri thức để giải thích vì sao một CVE đáng xem xét, điều kiện nào cần kiểm tra, nguồn nào hỗ trợ. Đây phù hợp hơn với ưu tiên CVE hoặc chuẩn bị giả thuyết kiểm chứng. Không dùng một đoạn hướng dẫn do LLM sinh làm nhãn chuẩn rằng website có lỗ hổng. Chưa cần huấn luyện T5 để có thử nghiệm đầu tiên.

## 4. Áp dụng vào thí nghiệm trước, chưa chốt hướng nghiên cứu

Một mục tiêu web được quan sát từ ngoài bằng HTTP; người dựng lab lưu phiên bản và cấu hình thật ở hồ sơ riêng để chấm. Scanner không được đọc inventory qua SSH rồi coi như đã nhận diện thành công từ web.

Nếu chọn hướng 1, so sánh baseline nhận diện từ banner/chuỗi version công khai với phương pháp kết hợp nhiều dấu hiệu HTTP. Đo độ đúng của version/range, tỷ lệ Unknown và số request. Đây khác baseline Ubuntu upstream-versus-package cũ.

Nếu chọn hướng 2, giữ cùng bộ CVE ứng viên cho hai phương pháp: baseline xếp theo tiêu chí đơn giản được định nghĩa rõ (ví dụ CVSS), phương pháp đề xuất thêm bằng chứng về sản phẩm/version/điều kiện web. Đo precision@k/recall@k với nhãn liên quan/áp dụng được định nghĩa trước; CVSS không phải xác suất website bị khai thác.

Nếu chọn hướng 3, so sánh khớp version đơn thuần với kiểm tra tiền điều kiện không khai thác. Phải thống nhất mức bằng chứng cho nhãn Confirmed/Not applicable/Unknown và ranh giới phép thử với trợ giảng. PoC trong lab có thể là bằng chứng bổ sung riêng nếu được chọn, không phải điều scanner bắt buộc chạy trên mọi mục tiêu.

Không trộn các thước đo trên thành một con số accuracy duy nhất. Không lấy Unknown làm an toàn. Chưa có kết quả thực nghiệm web nào trong lần đọc này.

## 5. Câu hỏi trao đổi với trợ giảng

Sau khi diễn giải cách hiểu đề tài lớn và hai bài, hỏi: mục tiêu chính nên là nhận diện version/range, ưu tiên CVE, hay kiểm chứng không khai thác? Web interface gồm server, framework, ứng dụng/plugin nào? Scanner được phép quan sát HTTP ở mức nào, có authentication không? Với câu hỏi được chọn, nhãn chuẩn cần advisory/config thật hay phải có reproduction trong lab?

Hai bài chỉ là hai tài liệu khởi đầu theo gợi ý của trợ giảng, chưa đủ để khẳng định đã khảo sát toàn bộ SOTA về web fingerprinting/triage/non-exploit validation.
