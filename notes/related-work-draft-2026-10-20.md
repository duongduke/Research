# Tổng quan nghiên cứu liên quan

> **Trạng thái:** bản nháp phục vụ rà soát, ngày 2026-10-20.
> Trích dẫn dùng khóa `[KEY]`; thư mục tài liệu tham khảo sẽ được viết ở bước sau.
> Mọi số liệu dưới đây lấy từ `notes/literature-references-2026-10-20.md`.

## Mở đầu: ba mức của cùng một câu hỏi

Câu hỏi “CVE này có áp dụng cho hệ thống web đang chạy không?” gồm ba mức nối tiếp:
phiên bản đang chạy có nằm trong dải bị ảnh hưởng; triển khai cụ thể có thỏa mãn các
điều kiện để lỗi gây tác động; và lỗi đã thực sự bị khai thác được chưa. Công cụ quét
thường gộp ba mức này, tạo ra cả báo động sai lẫn cảm giác an toàn không có căn cứ.
Đồ án đặt mức thứ hai làm trọng tâm.

## 1. Nhận diện phiên bản bị ảnh hưởng

VAVI đánh giá 12 công cụ xác định phiên bản bị ảnh hưởng trên 1.128 CVE của các dự án
C/C++ và ghi nhận không công cụ nào vượt quá 45% độ chính xác [VAVI]. Với đồ án, khớp
phiên bản chỉ là điều kiện cần; sai số ở mức thứ nhất sẽ lan xuống mức thứ hai nếu hai
bước không tách bạch.

VERCATION kết hợp phân tích tĩnh, mô hình ngôn ngữ lớn và so khớp mã nguồn để xác định
phiên bản phần mềm mã nguồn mở bị lỗi, báo cáo 202 phiên bản bị ảnh hưởng ghi sai trong
NVD [VERCATION]. Dữ liệu tham chiếu công khai vì thế không hoàn toàn nhất quán; khi các
nguồn mâu thuẫn, phương pháp phải xử lý xung đột theo phạm vi và nguồn.

Vuln2Action dùng mô hình T5 sinh các bước tái tạo lỗi và liên kết tài liệu exploit trên
cơ sở hợp nhất CVE, CWE, CPE, CAPEC và Exploit-DB [VULN2ACTION]. Hạn chế chính là đầu
ra không được kiểm chứng bằng thực thi, và chỉ khoảng 0,4% số CVE trong NVD có exploit
trên Exploit-DB. Đồ án vì thế lấy nhãn chuẩn từ tái hiện trong môi trường cách ly thay
vì từ văn bản sinh ra.

## 2. Đánh giá mức áp dụng và khả năng khai thác

Supply Chain Reaction dùng reachability ở mức hàm, trên Debian giảm 28% số binary bị
báo ảnh hưởng và 30% số CVE trên mỗi binary [SUPPLYCHAIN]. CPVRA phân tích reachability
cho lỗ hổng thư viện bên thứ ba kèm kiểm tra tính thỏa mãn của ràng buộc đường đi, giảm
khoảng 40% báo động sai so với baseline [CPVRA]. Younis và cộng sự đặt nền móng cho
hướng này với điểm vào của bề mặt tấn công và reachability [YOUNIS]. SojiTantei áp dụng
reachability ở mức lời gọi hàm cho gói npm: 68 trong 78 lỗ hổng có ít nhất một máy khách
“sạch”, tức phiên bản bị ảnh hưởng nhưng mã chứa lỗi không được gọi tới [SOJITANTEI].

Cả bốn đều cần mã nguồn, đồ thị lời gọi hoặc thông tin phụ thuộc. Với mục tiêu web quan
sát từ ngoài, ta không có mã nguồn bản đang chạy và không dựng được đồ thị lời gọi của
plugin đã cài. Giá trị của nhóm này nằm ở khái niệm: một CVE chỉ áp dụng nếu tồn tại
đường gây tác động không bị chặn. Ở mức thứ hai, “bị chặn” được biểu diễn bằng điều
kiện cấu hình quan sát được thay cho đồ thị lời gọi. Khi không quan sát được điều kiện
đó, kết luận đúng là chưa xác định.

## 3. Ưu tiên hoá và dự đoán khai thác

EPSS cung cấp xác suất một lỗ hổng bị khai thác trong 30 ngày, dựa trên mô hình dữ liệu
công khai ở mức quần thể [EPSS]. Giá trị của nó là xếp hạng nguồn lực, không phải phán
quyết cho một triển khai: điểm cao không chứng minh CVE áp dụng, điểm thấp không loại
trừ. Dùng EPSS như bằng chứng áp dụng sẽ làm lẫn mức thứ hai với mức thứ ba.

## 4. Nhận diện ứng dụng web qua HTTP

WASABO khảo sát fingerprinting ứng dụng web qua HTTP: 94,8% trường hợp được nhận diện
trong điều kiện lý tưởng, nhưng công cụ thường không đưa ra được một phiên bản duy nhất
và dứt khoát [WASABO]. Với đồ án, phiên bản suy ra từ HTTP là suy luận có sai số, không
phải dữ kiện; 94,8% là giới hạn trên trong điều kiện thuận lợi, không phải độ chính xác
kỳ vọng. Khi tín hiệu mờ hoặc xung đột, kết luận phù hợp là chưa xác định.

## 5. Khoảng trống và hướng của đồ án

Bức tranh thu được là phân mảnh. Nhận diện phiên bản còn yếu và dữ liệu tham chiếu có
lỗi; reachability trả lời đúng câu hỏi “bị ảnh hưởng khác với áp dụng” nhưng đòi hỏi mã
nguồn; EPSS dự báo ở mức quần thể; fingerprinting HTTP không bảo đảm một phiên bản duy
nhất. Không công trình nào trong số này đánh giá mức thứ hai cho một triển khai web đang
chạy, chỉ từ dữ liệu CVE công khai và quan sát HTTP.

Đồ án lấp khoảng trống đó bằng cách hợp nhất bốn nguồn — CPE, NVD, thông báo nhà cung
cấp và phản hồi HTTP — theo luật ưu tiên có phân biệt phạm vi, cho phép trả `Unknown`
khi bằng chứng không đủ, và so sánh với bốn phương pháp dùng một nguồn trên cùng bộ nhãn
chuẩn. Nhãn chuẩn được xác lập độc lập bằng tái hiện trong sandbox trên 32 mã CVE, nên
kết luận được đối chiếu với hành vi thật của hệ thống chứ không với văn bản mô tả. Kết
quả thực nghiệm cho thấy nhiều tiền điều kiện không quan sát được qua HTTP, tạo ra một
“trần” về coverage; đóng góp của đồ án là đo được giới hạn đó và phân biệt rõ ba lớp
kết luận.

---

### Ghi chú biên tập (không thuộc nội dung chương)

- Khóa đã dùng: `VAVI`, `VERCATION`, `VULN2ACTION`, `SUPPLYCHAIN`, `CPVRA`, `YOUNIS`,
  `SOJITANTEI`, `EPSS`, `WASABO`. Khóa tùy chọn chưa dùng: `IVDR`, `EPSSV3`.
- Cần đối chiếu lại với PDF trong `paper/` trước khi chốt: con số 45% của VAVI, con số
  202 của VERCATION, và cách diễn đạt “94,8% trong điều kiện lý tưởng”.
- Không câu nào trong bản nháp khẳng định kết quả của đồ án vượt các công trình trên;
  phần 5 chỉ mô tả khoảng trống và thiết kế đánh giá.
