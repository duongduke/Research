# Review bộ rule fusion — 10/10/2026

**Phạm vi:** `notes/fusion-design-2026-10-10.md`, đối chiếu D-003, D-008,
D-010, D-016/D-017; ground-truth protocol; registry CVE; tài liệu khảo sát fusion
và các artifact HTTP của pilot. Không chạy lab hoặc đo kết quả mới.

**Trạng thái:** đề xuất thiết kế, ghi ở D-018 **PROVISIONAL**. Review không sửa
các quyết định ACCEPTED và không phê duyệt phương pháp bằng việc ghi nhận nó.

## 1. Nhận xét chung

Hướng quyết định theo điều kiện phù hợp với câu hỏi về applicability ở mức triển
khai. Bản nháp đã tách được vai trò của dải phiên bản, bản vá và tiền điều kiện;
không cộng ba lần một thông tin bị lặp; giữ Unknown khi thiếu bằng chứng. Đây là
cơ sở tốt để viết một thuật toán có thể giải thích và kiểm tra.

Cần chỉnh mô hình bằng chứng và định nghĩa phương pháp so sánh trước khi khóa
thiết kế. Không nên giải quyết những điểm này bằng một tổng điểm hoặc số nguồn
đồng thuận: nhiều nguồn cùng nói phiên bản affected vẫn không xác nhận được
trạng thái 2FA, quyền truy cập hay bản vá của triển khai đang quan sát.

## 2. Đề xuất cho bốn điểm mở

| Điểm | Lựa chọn đề xuất cho bản đầu tiên | Phần còn cần kiểm chứng |
|---|---|---|
| 1. Trọng số | Luật cố định theo từng khẳng định; xử lý trùng lặp và mâu thuẫn trước khi kết luận. Khóa luật trước đánh giá, không chọn luật sau khi xem kết quả benchmark. | Quy tắc ưu tiên phải ghi phạm vi sản phẩm/build, nhánh phiên bản và căn cứ; không mặc định mọi advisory đều thắng mọi dữ liệu NVD. |
| 2. Dấu hiệu HTTP | Lập và kiểm tra bảng tiền điều kiện–dấu hiệu trong quá trình dựng từng CVE. Tách dấu hiệu quan sát của phương pháp khỏi fixture/PoC phục vụ nhãn chuẩn. | Với từng điều kiện: request/path, access model, budget, dấu hiệu dương/âm, trường hợp nhập nhằng và đối chứng. Chưa quan sát được thì giữ Unknown. |
| 3. Phân bố tình huống | Ít nhất 30 CVE **khác nhau**, mỗi CVE có các trạng thái triển khai phù hợp. Gắn nhãn tình huống để phân tích theo nhóm; không đặt trước các ca phải làm fusion thắng. | Số ca mỗi nhóm chỉ xác định sau kiểm tra khả thi và ghi selection log. Không tạo quota backport/CPE sai khi chưa có trường hợp thật được kiểm chứng. |
| 4. Đủ bằng chứng | Dựa trên việc xác định được các điều kiện bắt buộc của một đường tác động, thay vì đếm nguồn đồng thuận. | Cần mô tả phạm vi các đường tác động và cách mỗi predicate được gán True/False/Unknown. |

Không chọn học trọng số làm phương pháp chính ở giai đoạn này. Nhiều trạng thái
của cùng CVE không tạo ra nhiều CVE độc lập để huấn luyện. Nếu bổ sung mô hình học
sau này, cần nhóm phát triển/đánh giá tách theo CVE và kiểm soát rò rỉ giữa các ca.

EPSS dự báo hoạt động khai thác CVE trong 30 ngày ở mức quần thể; không trực tiếp
xác định CVE applicable với một triển khai. Vì vậy, có thể tham khảo cách tổ chức
đánh giá của EPSS, nhưng không lấy EPSS làm lý do đủ để học trọng số cho bài toán
này. [FIRST — Using EPSS](https://www.first.org/epss/using-epss).

## 3. Các sửa đổi cần thực hiện trong bản nháp

### R1 — Giữ bốn kênh đầu vào, làm rõ các phương pháp so sánh

**Căn cứ:** fusion-design §3, dòng 26–50; D-016/D-017.

D-016 đang ACCEPTED với bốn phương pháp đơn và fusion, trong khi bản nháp chỉ
còn ba, bỏ HTTP version-string-only. Lập luận HTTP cần kiến thức về CVE để diễn
giải là đúng, nhưng chưa cho phép bỏ một phương pháp đã ghi trong quyết định.

Đề xuất giữ bốn kênh thu thập theo D-017, rồi lập bảng input/luật thật cho từng
phương pháp theo D-016. Ghi rõ E5 là thông tin nhận diện target dùng chung của các
phương pháp tra cứu, nên “single-source” ở đây cần được định nghĩa chính xác.
HTTP version-string-only cũng phải khai báo lấy bảng CVE–phiên bản ở đâu; nếu có
bảng dùng chung thì đó là phương pháp **chỉ dùng version string về target**, không
phải suy ra CVE chỉ từ một chuỗi HTTP không có kiến thức tham chiếu.

CPE-only và NVD-only hiện dùng cùng dải CPE và cùng luật; CVSS/CWE không đổi nhãn.
Nếu input thực tế giống nhau thì dự đoán giống nhau là điều phải báo cáo. Không
bịa sự khác biệt hoặc coi hai hàng đó là hai bằng chứng độc lập. Muốn đổi tập
phương pháp của D-016 thì cần một quyết định sửa đổi được chấp nhận; D-018 chưa
thực hiện thay đổi đó.

### R2 — E5 là nhận diện suy ra từ HTTP; E4 chưa chứng minh target đã vá

**Căn cứ:** fusion-design dòng 21, 56, 60; registry mục nginx;
`experiments/pilot-3cve/artifacts/http-verification.txt`.

Đổi “version thực tế” thành **sản phẩm/phiên bản/build suy ra từ HTTP**, kèm dấu
hiệu và mức phân giải. Phiên bản pin trong image, package revision hoặc config
đọc qua SSH thuộc ground truth; không tự động trở thành input của phương pháp.
Pilot đã cho thấy WordPress plugin có dấu hiệu phiên bản, còn Drupal/Roundcube
không có phiên bản chính xác dưới quan sát unauthenticated đã thực hiện.

Biết một gói Ubuntu đã backport bản vá khác với biết target đang chạy đúng gói
đó. Header `nginx/1.18.0 (Ubuntu)` chưa xác nhận package revision. Muốn kết luận
Not Applicable do backport, cần bằng chứng được phép quan sát để nối target với
build đã vá, hoặc dấu hiệu phân biệt bản vá đã được kiểm chứng. Nếu thông tin
hiện có còn phù hợp với cả build vá và chưa vá, nhánh bản vá chưa được giải quyết.
Không dùng package metadata trong lab để làm fusion thắng; kết quả Unknown ở
ca này vẫn có ý nghĩa và phải được báo cáo.

### R3 — Gom các khẳng định tương đương; không xóa khác biệt giữa nguồn

**Căn cứ:** fusion-design dòng 24, 57–59, §4.2.

E1–E6 nên gọi là **sáu loại bằng chứng**, không phải sáu đơn vị nhỏ nhất. Đơn vị
thực tế là một khẳng định về một target/CVE/điều kiện có phạm vi và provenance.
Ví dụ: “phiên bản plugin thuộc nhánh affected”, “2FA bật”, “build này chứa bản vá”.

Các khẳng định E1 tương đương sau chuẩn hóa được gom về một nội dung, giữ toàn
bộ nguồn gốc và snapshot. Các dải khác nhau vẫn là khác biệt cần giải thích;
không tự lấy union/intersection hoặc ép chúng thành một khẳng định đồng thuận.
Giữ bốn kênh dữ liệu ở collector, khử trùng ở mức nội dung, phù hợp với D-017.

Không viết mặc định “NVD CPE lấy từ advisory” cho mọi bản ghi nếu chưa xác minh
provenance. CPE là cách nhận diện nền tảng; dữ liệu CPE Match của NVD là một phần
của thông tin applicability theo CVE, nên phải chỉ rõ dataset/API mà baseline
dùng. [NVD — Product APIs, Match Criteria](https://nvd.nist.gov/developers/products).

Ưu tiên nguồn cần áp dụng cho **cùng một câu hỏi và cùng phạm vi**. Advisory
upstream nói phiên bản affected và distro advisory nói một package backport đã
vá không nhất thiết mâu thuẫn. Một advisory cập nhật, đúng nhánh/build có thể
giải thích hoặc thay thế thông tin cũ. Nếu vẫn còn hai khẳng định đối lập cùng
áp dụng cho target mà không giải được, predicate đó giữ Unknown.

### R4 — Không đồng nhất thiếu quan sát với thiếu tiền điều kiện

**Căn cứ:** fusion-design dòng 43–47, 56, 61–68.

Advisory không nhắc một tiền điều kiện chưa có nghĩa CVE vô điều kiện. Tương tự,
không thấy dấu hiệu feature chưa có nghĩa feature tắt. 404, 403 hoặc timeout có
thể đến từ route, quyền truy cập, proxy hoặc budget quan sát. Chỉ gán False khi
phép quan sát đã được kiểm chứng là đủ để loại điều kiện trong access model đó.
E6 không mạnh hơn E3 theo thứ hạng chung: E3 định nghĩa điều kiện cần, E6 giúp
xác định điều kiện đó có trên target hay không.

Không dừng toàn bộ pipeline ngay khi thiếu phiên bản chính xác. Có thể xác định
được cả dải ứng viên đều không affected, hoặc xác nhận mọi đường tác động trong
phạm vi đều bị chặn dù chưa biết bản vá. Ngược lại, một đường còn điều kiện chưa
rõ thì không được kết luận âm bằng việc chỉ kiểm tra những đường dễ quan sát.

Advisory-only khai báo E4 nhưng chưa có luật dùng E4; cần bổ sung xử lý build/bản
vá với cùng yêu cầu liên kết target–build như fusion. Bỏ nhãn “baseline chuẩn
ngành” khi chưa có tài liệu chứng minh đúng baseline và luật đang dùng.

### R5 — Chọn ca và khóa luật trước đánh giá

**Căn cứ:** fusion-design dòng 72–74, 91; CURRENT_STATE §25.

“Ẩn version” là một điều kiện quan sát, không phải nhãn CVE. Config tắt và backport
là trạng thái triển khai; CPE sai là vấn đề metadata. Các nhóm có thể giao nhau,
nên dùng tag và báo riêng số CVE, số deployment/case và phân bố nhãn chuẩn.

Ưu tiên đối chứng affected/fixed, thêm config on/off khi đúng với CVE. Backport
và metadata sai cần căn cứ riêng. Nếu chủ động làm sai metadata hoặc che header
để thử độ bền, ghi rõ đó là thử nghiệm can thiệp, tách khỏi dữ liệu quan sát tự
nhiên. Không loại ca thiếu dấu hiệu HTTP chỉ để tăng coverage hoặc chọn ca sau
khi đã biết fusion có lợi.

Có thể dùng pilot để phát triển và kiểm tra bảng dấu hiệu. Trước đánh giá cuối,
khóa collector, bộ luật và bảng dấu hiệu; ghi riêng các CVE đã dùng phát triển.
Không đổi precedence/ngưỡng dựa vào kết quả của chính tập báo cáo cuối.

## 4. Luật kết luận đề xuất

Mỗi predicate có giá trị True, False hoặc Unknown, kèm căn cứ. Đặt:

- `B`: target chứa build/code affected, sau khi xét nhận diện, dải và bản vá.
- `P_i`: tất cả điều kiện bắt buộc của đường tác động i trong phạm vi/access model.

Với từng đường: `P_i = True` khi tất cả điều kiện là True; `P_i = False` khi ít
nhất một điều kiện bắt buộc là False; còn lại là Unknown.

| Kết quả | Điều kiện |
|---|---|
| Applicable | `B = True` và tồn tại một đường có `P_i = True`. |
| Not Applicable | `B = False`, **hoặc** mọi đường liên quan có `P_i = False` với phạm vi đường đã xác định đủ. |
| Unknown | Các trường hợp còn lại; giữ lý do và predicate chưa giải được. |

Đây là cấu trúc luật để dự đoán; không thay thế bằng chứng reproduction dùng
cho nhãn chuẩn theo D-010/D-015. Không yêu cầu phương pháp kích hoạt lỗi để xác
nhận Applicable, và không lấy thất bại PoC làm bằng chứng của phương pháp.

Ví dụ kiểm tra luật trước triển khai:

| Bằng chứng | Dự đoán dự kiến |
|---|---|
| Ba nguồn lặp cùng dải affected; 2FA chưa biết và là điều kiện cần của đường duy nhất | Unknown, không phải Applicable do “3 phiếu”. |
| Build affected được nhận diện; mọi điều kiện của một đường đã xác định True | Applicable. |
| REST tắt nhưng JSON:API còn bật; một điều kiện khác của đường JSON:API chưa biết | Unknown, chưa đủ kết luận âm. |
| Mỗi đường đều có ít nhất một điều kiện bắt buộc được xác định False | Not Applicable. |
| HTTP nối được target với build đã vá theo bản ghi phù hợp | Not Applicable, không cần thêm config tắt. |
| Chỉ biết upstream version và distro có bản vá, chưa biết revision của target | Chưa được kết luận đã vá từ E4; Unknown nếu không có căn cứ khác đủ quyết định. |

## 5. Đánh giá và giới hạn phát biểu

Giữ bảng dự đoán ba kết quả so với nhãn chuẩn hai lớp. Báo precision(Applicable),
recall với toàn bộ ground-truth Applicable ở mẫu số, coverage và Unknown rate
trên cùng tập nhãn đã xác định. Báo số kết luận dương sai, âm sai và Unknown
riêng; giảm false mapping bằng cách trả Unknown nhiều hơn cần thể hiện qua
coverage/recall. Khi gộp nhiều trạng thái của một CVE, trình cả kết quả theo ca
và theo CVE để CVE nhiều trạng thái không lấn át toàn bộ kết quả.

Khảo sát tài liệu hiện là bước đầu. Những nhận định “không ai làm” hoặc mô hình
GBDT tự bảo đảm xử lý đúng dư thừa chưa được khảo sát hiện tại chứng minh. Nên
viết “chưa tìm thấy trong phạm vi tài liệu đã khảo sát” và tách các bài ưu tiên
CVE khỏi phương pháp xác định applicability. Chưa có kết quả để khẳng định
fusion thắng, đặc biệt trong nhóm hidden-version/backport.

**Bước tiếp theo cụ thể:** sửa R1–R4 trong bản nháp, lập bảng dấu hiệu cho các
CVE pilot, kiểm tra các ví dụ luật ở §4, rồi khóa quy trình trước đánh giá cuối.
Các con số phân bố và predicate HTTP của 26 CVE còn lại vẫn là việc cần đo,
không phải quyết định có thể xác lập chỉ bằng thảo luận.
