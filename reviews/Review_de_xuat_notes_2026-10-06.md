# Review các đề xuất trong notes — 06/10/2026

## Kết luận

Hướng nghiên cứu mới đã rõ và nhất quán hơn lần review 04/10: **fusion nhiều nguồn để đánh giá CVE applicability của triển khai web cụ thể**, với reproduction tách riêng để kiểm chứng nhãn. Đây là cơ sở hợp lý để hoàn thiện protocol và làm pilot. Chưa nên nâng D-011 lên ACCEPTED hoặc khóa danh sách ≥30 CVE theo bản hiện tại.

Những điểm cần sửa trước là: nguồn quan sát cấu hình của phương pháp; phân biệt Unknown của ground truth và Unknown của dự đoán; luật nhãn âm; đếm CVE khác case; và kiểm chứng điều kiện/khả năng dựng từng CVE. Chuyển sang CMS/webmail là lựa chọn đã ghi nhận, không cần mở lại câu hỏi chọn hướng 1/2/3.

## Phạm vi và trạng thái bằng chứng

Đọc lại bốn file `context` theo AGENTS.md; tập trung vào toàn bộ `notes/ground-truth-protocol.md` và `notes/cve-selection-va-lab-ke-hoach-2026-10-06.md`. Đối chiếu `notes/cau-hoi-tro-giang.md`, ghi chú hai bài báo, LaTeX, Markdown thiết kế, quyết định D-001–D-011, và artifacts Apache trong `experiments/reproduce-cve-2021-41773/`.

Workspace có thư mục **notes**, không có thư mục `note`. D-007–D-010 được xem là các quyết định ACCEPTED hiện hành. D-011 vẫn PROVISIONAL. Pool WordPress/Drupal/Roundcube và việc tạm hoãn framework được note ghi là đã thống nhất với người dùng; danh sách CVE, KEV và hạ tầng vẫn là đề xuất. Chưa có dataset, scanner hoặc kết quả so sánh mới.

Kiểm tra web có chọn lọc bằng advisory của Roundcube, Drupal, LiteSpeed, bài công bố của nhóm phát hiện Wordfence, tài liệu Roundcube và WordPress.org. Đây **không phải xác minh hoàn chỉnh cả 14 CVE**: chưa tải các phiên bản, kiểm tra checksum/image, hay chạy PoC ứng viên. Một số trang CVE.org cần JavaScript; trang catalog CISA trả 403. Không lấy việc không mở được trang làm bằng chứng rằng CVE hoặc tài liệu không tồn tại.

## Những điểm đã cải thiện

- Protocol dùng bộ tứ `(product, version/build, configuration, CVE)`, phù hợp mức kết luận đã chọn.
- Reproduction, config và dự đoán của phương pháp được phân vai; người gán nhãn không xem dự đoán.
- Có quy tắc **PoC thất bại không tự sinh nhãn âm**, và có vết truy artifact.
- Đã ghi ≥30 CVE là yêu cầu, đưa Apache về pilot và ưu tiên CMS/webmail.
- Có tiêu chí khả năng dựng/tái tạo và ý định đa dạng hóa tập ca; chưa trình các ứng viên như kết quả thực nghiệm.

## Phát hiện theo mức độ ảnh hưởng

### R1 — P1: Chưa chỉ rõ phương pháp quan sát tiền điều kiện qua HTTP bằng cách nào

**Căn cứ:** D-003; protocol dòng 14–18 và 28–29; LaTeX dòng 215, 228; selection note mục 3–6.

Biết từ advisory rằng lỗi cần một tính năng bật là **tri thức chung về CVE**. Biết website đang bật tính năng đó là **bằng chứng về mục tiêu cụ thể**. Các nguồn công khai CPE/advisory/history/patch không tự cung cấp thông tin thứ hai.

Hiện protocol mô tả ground truth tốt hơn đầu vào của fusion. Nếu fusion được cấp `config=true/false` từ hồ sơ người dựng lab, phương pháp có thể trả lời đúng nhưng đánh giá sẽ vi phạm D-003. “Configuration là phần định danh case” không đồng nghĩa scanner được đọc trực tiếp trường configuration.

**Kiến nghị:** mỗi CVE có bảng tiền điều kiện, dấu hiệu HTTP dự kiến, cách thu được dấu hiệu trong ngân sách quan sát, và thông tin chỉ dành cho ground truth. Quy định rõ có tài khoản hay chỉ unauthenticated; tránh suy “không thấy endpoint” thành “tính năng tắt”. Những phép quan sát chưa đánh giá được độ đặc hiệu chỉ là dấu hiệu, không mặc định bằng chứng chắc chắn.

Nếu hai triển khai khác nhãn nhưng có cùng bằng chứng cho phép, phương pháp không thể phân biệt chắc chắn bằng chính bằng chứng đó. Đây là giới hạn cần báo cáo và là một vai trò hợp lệ của Unknown.

### R2 — P1: Unknown của phương pháp đang bị trộn với Unknown của nhãn chuẩn

**Căn cứ:** protocol dòng 40–41; selection note dòng 42 và 65–66.

“Version không xác định được” có hai trường hợp khác nhau:

- Người dựng lab biết version, config và kết quả reproduction, nhưng scanner không đọc được version từ HTTP: **ground truth có thể đã xác định**, còn dự đoán có thể Unknown.
- Người gán nhãn chưa xác định được trạng thái thật hoặc phép thử chưa đáng tin: **ground truth chưa giải quyết được**.

Không nên tạo đủ ba lớp bằng cách gán Unknown cho những ca chỉ thiếu bằng chứng phía scanner. Điều đó có thể thưởng cho việc từ chối kết luận thay vì đo khả năng đánh giá đúng trạng thái thật.

**Kiến nghị PROPOSED:** giữ đầu ra `{Applicable, Not Applicable, Unknown}` đã chọn, nhưng tách trạng thái nhãn tham chiếu và trạng thái bằng chứng quan sát. Báo tỷ lệ kết luận (coverage), tỷ lệ Unknown, precision/recall trên nhãn đã kiểm chứng và cách abstention được tính vào metric. Những ca ground truth thực sự chưa giải quyết nên có báo cáo riêng; không âm thầm loại khỏi mẫu số.

Ví dụ minh họa thiết kế, **chưa phải dữ liệu mới**:

| Triển khai | Ground truth sau kiểm chứng | Bằng chứng scanner nhận được | Kết luận có thể đưa ra |
|---|---|---|---|
| Bản bị ảnh hưởng, điều kiện bật | Applicable | Đủ xác nhận version và điều kiện | Applicable |
| Cùng bản, điều kiện cần tắt | Not Applicable cho điều kiện/phạm vi đã định nghĩa | Đủ xác nhận điều kiện vắng | Not Applicable |
| Bản bị ảnh hưởng, điều kiện bật | Applicable | Version/điều kiện bị che, không đủ suy ra | Unknown |

Hàng cuối không phải ground-truth Unknown. Cần kiểm tra riêng liệu các dấu hiệu ở hai hàng đầu thực sự thu được qua HTTP.

### R3 — P1: Luật “ngoài dải affected → Not Applicable, đóng luôn” cần điều kiện tin cậy

**Căn cứ:** protocol dòng 37–40; RQ tập trung giảm mapping sai bằng nhiều nguồn.

Nếu dải lấy từ một nguồn cần đánh giá vốn có thể thiếu/sai, dùng chính dải đó đóng nhãn âm sẽ đưa sai số của nguồn vào ground truth. Dải affected, build/package identity, patch và thông tin nguồn phải đủ rõ trước khi ra nhãn; trường hợp thiếu dữ liệu không phải ngoài dải chắc chắn.

Luật 3 có bước phân tích config là một cải thiện, nhưng phải xác định **tiền điều kiện thật sự cần thiết cho tác động đang đánh giá** và loại trừ đường thay thế liên quan. Không đủ để thấy một feature tắt hoặc một URL trả 403 rồi gọi toàn deployment là Not Applicable.

Hai ví dụ từ danh sách ứng viên cho thấy vấn đề này:

- **Drupal CVE-2019-6340:** advisory liệt kê cả REST core và các web-services module khác. Tắt REST core chưa đủ nếu JSON:API/đường khác liên quan còn bật. [Drupal SA-CORE-2019-003](https://www.drupal.org/sa-core-2019-003).
- **LiteSpeed Cache CVE-2024-28000:** vendor nêu hash vẫn có thể được sinh/lưu khi crawler không bật. Không dùng “crawler off” làm nhãn âm mặc định. [LiteSpeed advisory](https://blog.litespeedtech.com/2024/08/21/security-update-for-litespeed-cache/).

**Kiến nghị:** định nghĩa nhãn theo CVE, tác động và access model; ghi tập tiền điều kiện, căn cứ vì sao điều kiện vắng đủ bác bỏ ca, và kiểm tra bằng cặp đối chứng. Không bắt buộc source/binary cho mọi ca; những ca khó cần mức bằng chứng đủ mạnh hoặc giữ trạng thái chưa xác định.

### R4 — P1: ≥30 CVE khác với ≥30 case

**Căn cứ:** D-010; selection note dòng 15 và 29; protocol dòng 61 lại ghi “≥30 case”.

Theo D-010, mục tiêu là **ít nhất 30 CVE ID khác nhau**. Một CVE dựng ở ba trạng thái vẫn là một CVE, ba case. Các slot chưa có ID chưa được tính; biến thể config không bù được số CVE còn thiếu.

**Kiến nghị:** theo dõi riêng `n_unique_cves`, `n_deployments`, `n_cases`, `n_observation_conditions`. Có thể xây affected+điều kiện thỏa, affected+điều kiện cần vắng, và fixed cho các CVE phù hợp. Nếu 30 CVE đều có ba trạng thái thì là 90 case, chưa kể biến thể quan sát; đây là phép tính workload, không phải cam kết rằng mọi CVE đều có cấu hình âm thuận tiện.

Các case cùng CVE phụ thuộc nhau. Không chia ngẫu nhiên những config/version của cùng CVE vào cả phần chỉnh luật và phần đánh giá rồi coi là dữ liệu độc lập. Cần báo kết quả theo case và theo nhóm CVE; giữ phần đánh giá chưa dùng để điều chỉnh phương pháp.

### R5 — P1: Danh sách ứng viên có lỗi phân loại và chưa đủ dữ liệu để “chốt ngay”

**Căn cứ:** selection note dòng 46–66.

**Lỗi xác nhận được:** `CVE-2020-12625` của Roundcube là **XSS qua HTML độc hại**, không phải path traversal. Cùng thông báo vendor, path traversal/local-file-inclusion là `CVE-2020-12640`. Không tự thay CVE ID: cần chọn giữ ca XSS hay đổi ứng viên theo mục tiêu dataset. [Roundcube security updates 29/04/2020](https://roundcube.net/news/2020/04/29/security-updates-1.4.4-1.3.11-and-1.2.10).

14 ID hiện là ứng viên, không có 14 nhãn Applicable đã kiểm chứng. “CHỐT NGAY” và “nhãn dự kiến Applicable” dễ kéo việc chọn ca theo kết quả mong muốn. Tiêu đề phù hợp hơn là danh sách ưu tiên xác minh, cùng trạng thái verified/unverified thay cho nhãn chuẩn trước reproduction.

**Ví dụ ứng viên có điều kiện rõ:** công bố của nhóm phát hiện về **CVE-2024-10924 (Really Simple Security)** nêu dải 9.0.0–9.1.1.1, bản vá 9.1.2, và tiền điều kiện 2FA bật. Có thể khảo sát ca này cho pilot mức deployment; chưa chứng minh scanner quan sát được 2FA hoặc lab đã dựng được. [Wordfence, nhóm phát hiện](https://www.wordfence.com/blog/2024/11/really-simple-security-vulnerability/).

Các phép tái tạo XSS ở webmail còn phải kiểm tra ngữ cảnh render và thực thi trong trình duyệt; chỉ curl thấy một chuỗi HTML không tương đương xác nhận hành vi XSS. Nên ghi loại artifact cần có ngay khi xét khả thi.

### R6 — P2: Tiêu chí lựa chọn chưa đủ để chống cherry-picking và đo đóng góp

**Căn cứ:** selection note mục 3 và slot nginx dòng 74; baseline/fusion chưa cố định.

Chọn các CVE nổi tiếng, có PoC dễ chạy là tiêu chí khả thi hợp lý, nhưng tạo **mẫu tiện lợi/khả thi**, chưa đại diện cho mọi CVE web. Có tiêu chí không tự bảo đảm hết thiên lệch: cần pool ban đầu, nguồn/ngày chốt, ca được chọn, ca bị loại và lý do. Không chọn sau khi biết fusion thắng.

Pool ghi 3–4 plugin, danh sách đã có bốn plugin khác nhau, các slot còn thêm nhiều plugin/Drupal contrib; mục 8 lại ghi 4–5 plugin. Nên khóa giới hạn rõ để workload không tăng ngoài dự kiến. Phân tầng tám loại lỗi và severity là mục tiêu bao phủ; không tự ép đủ mọi loại nếu làm hỏng tiêu chí chọn đã xác định.

Một baseline CPE-only chỉ nhìn version có thể không phân biệt cùng-version/khác-config. Nếu fusion được thêm quan sát HTTP, lợi ích đo được bao gồm **thêm thông tin mục tiêu** và **cách kết hợp thông tin**. Cần mô tả đúng so sánh đó; muốn quy phần cải thiện cho fusion, cân nhắc baseline đơn nguồn mạnh hơn và ablation có/không có bằng chứng tiền điều kiện trên cùng pool quan sát, cùng budget. NVD/vendor/patch cũng có thể chung nguồn gốc; không dùng số URL như số phiếu độc lập.

Yêu cầu ≥30 từ trợ giảng là phạm vi tối thiểu, chưa phải chứng minh cỡ mẫu đủ cho mọi kết luận. Báo phân bố nhãn, chênh lệch điểm phần trăm, phân tích lỗi và độ bất định theo nhóm CVE; một bộ gồm phần lớn Applicable dễ làm accuracy thiếu thông tin.

### R7 — P2: KEV giúp mô tả ưu tiên, không chứng minh applicability của website

**Căn cứ:** selection note dòng 44, 110.

KEV phản ánh bằng chứng khai thác ngoài thực tế và được CISA dùng để ưu tiên xử lý. Suy “CVE thuộc KEV → deployment này Applicable” là không hợp lệ. [CISA giải thích việc bổ sung KEV dựa trên active exploitation](https://www.cisa.gov/news-events/alerts/2025/08/12/cisa-adds-three-known-exploited-vulnerabilities-catalog).

Có thể dùng KEV làm metadata/phân tầng nếu ghi giới hạn. Chưa nên gán trọng số dương cho nhãn applicability chỉ vì có tên trong KEV. Chọn chỉ ca KEV còn làm tập đánh giá lệch về CVE đã có bằng chứng khai thác. Phân biệt mức rủi ro/ưu tiên với trạng thái deployment là cần thiết để giữ hướng 3 đã chọn.

### R8 — P2: Hạ tầng tuần tự hợp lý, nhưng dependencies/reset chưa được tính đủ

**Căn cứ:** selection note mục 7.

Một VM và workload tuần tự là thiết kế có thể dùng cho pilot. Spec 4 vCPU/8 GB/60 GB và kích thước image trong note là **ước lượng**, chưa có đo đạc hay manifest để khẳng định đủ cho danh sách cuối. Không cần thêm VM chỉ để tách input và ground truth; cần tách dữ liệu được phép thấy.

Roundcube là webmail client, không chỉ PHP+MariaDB: nhánh 1.5 liệt kê IMAP, HTTP, SMTP cùng PHP/DB. Những ca mail cần test inbox/message/session có thể cần thêm mailbox backend và browser runner. Yêu cầu thay đổi theo version; đọc INSTALL đúng release của ca. [Roundcube INSTALL 1.5](https://raw.githubusercontent.com/roundcube/roundcubemail/release-1.5/INSTALL), [vendor lưu ý requirements theo version](https://github.com/roundcube/roundcubemail/wiki/Install-Requirements).

MariaDB dùng chung chỉ tiết kiệm được khi tương thích; cần database/user/data riêng và reset giữa ca, nhất là phép tái tạo làm đổi tài khoản hoặc dữ liệu. Dừng container không tự reset volume, inbox hay cookie trình duyệt. Manifest nên pin application/plugin, PHP, DB, web server và các dependency liên quan; lưu init/reset, fixture và checksum/digest.

Không có bảo đảm “mọi version cũ của plugin đều tải được”. Ticket chính thức của WordPress.org ghi trường hợp tag có nhưng ZIP chưa được tạo. Phải xác minh artifact cụ thể từng version, không khóa dataset bằng lời hứa chung. [WordPress.org ticket #5902](https://meta.trac.wordpress.org/ticket/5902).

Việc note ghi reproduction RCE là ứng viên không thay thế ranh giới đã chốt trong AGENTS/D-006. Bản review chỉ đọc và đánh giá thiết kế, không chạy các phép thử đó.

### R9 — P2: Apache pilot có kết quả dương thật, nhưng chưa là đối chứng đầy đủ

**Căn cứ:** `03-lab-traversal.txt`, `05-default-249-traversal.txt`, `06-logs.txt`, `config/decisive-diff.txt`, README pilot dòng 25–26, 80 và 94–96.

Artifact xác nhận 8083 trả 200 với marker 17 byte; 8081 chặn path bởi config; 8082 trả 404/400. Đây là bằng chứng hữu ích cho pilot. Tuy nhiên:

- README/state nói chỉ khác dòng authorization, nhưng `decisive-diff.txt` còn có Alias `/lab/`.
- Marker chỉ được chứng minh có trong 8083; tài liệu ghi 8081 không có marker. Chưa có hồ sơ fixture tương đương cho cả ba instance.
- 2.4.51 đang dùng config mặc định, không phải config nới quyền tương đương 8083. HTTP 404 riêng lẻ không đủ quy kết nguyên nhân cho bản vá; cần phối hợp advisory/log và control tương đương.

Kết quả dương không bị phủ nhận. Cần giới hạn diễn giải: đã tái tạo file disclosure và thấy log authorization chặn request ở instance mặc định; chưa chứng minh một thí nghiệm chỉ thay đúng một biến trên mọi instance. Giữ raw artifacts; sửa diễn giải và làm control bổ sung nếu pilot được đưa vào benchmark chính thức.

### R10 — P2: Tài liệu cũ và cách biện minh tính mới còn chưa theo quyết định mới

**Căn cứ:** `PROJECT.md` mục 2, 5, 6; `CURRENT_STATE.md` mục 6 và 11; `notes/cau-hoi-tro-giang.md` đầu file; `design/phuong-phap-nghien-cuu.md`; LaTeX dòng 143, 180–182, 214, 227–244; protocol dòng 54–55 và rationale D-011.

PROJECT/design vẫn ghi hướng chưa chọn hoặc Apache/nginx là chính; LaTeX còn bộ ba case và lab tập con; câu hỏi ghi chưa gửi dù checkpoint sau nói đã có trả lời. CURRENT_STATE mục 6 còn nói chưa có PoC/kết quả. Những phần này cần được đánh dấu lịch sử hoặc hòa giải với D-007–D-010, để lần đọc sau không mở lại quyết định.

LaTeX đã thêm mức deployment, nhưng vẫn gọi 44,9% của VAVI là “nguồn đơn”. Đó là accuracy exact-set của **công cụ đơn**, không đo CPE-only. Protocol/D-011 vẫn nói reproduce “lấp đúng khoảng trống Vuln2Action”: lab kiểm chứng nhãn classifier khác kiểm chứng bước do Vuln2Action sinh. Tính mới cần được biện minh từ bài toán/biểu diễn bằng chứng/cách kết hợp/evaluation phù hợp và literature liên quan; ghép hai bài gợi ý chưa đủ để kết luận novelty.

Câu LaTeX “cả ba mức không cần khai thác trực tiếp mục tiêu” cũng cần phân biệt: phương pháp có thể không khai thác website đang đánh giá; kết luận **đã khai thác thành công** vẫn cần bằng chứng thực thi cho đúng triển khai được kết luận. Bằng chứng lab không tự cho kết luận thành công trên website khác.

## Thứ tự làm tiếp được kiến nghị

Đây là đề xuất review, chưa áp dụng vào protocol:

1. Làm rõ R1–R4: access model, biểu diễn bằng chứng/nhãn, tiêu chuẩn âm, số CVE khác case và metric Unknown. Giữ D-011 PROVISIONAL trong bước này.
2. Lập registry CVE có `ID`, product/plugin slug, advisory, affected/fixed build, checksum/digest hoặc nguồn artifact, dependency, tiền điều kiện, dấu hiệu HTTP, kiểu kiểm chứng lab, chi phí dự kiến và lý do chọn/loại. Chưa gán nhãn chuẩn khi mới chọn ứng viên.
3. Pilot một nhóm nhỏ đại diện cho điều kiện cấu hình và workload khác nhau. Có thể khảo sát Really Simple Security, Drupal REST và Roundcube XSS; đây là gợi ý kỹ thuật từ nguồn trên, không tự khóa ba ca hoặc cấp phép thực thi.
4. Sau pilot, chốt subset sản phẩm/plugin, criterion chọn và registry ≥30 CVE khác nhau. Tách phần chỉnh luật khỏi phần đánh giá; không dùng kết quả pilot đã học để tuyên bố hiệu quả trên dữ liệu chưa thấy.
5. Hoàn thiện baseline/fusion/metric và đồng bộ bản trình bày theo quyết định. Không cần hỏi lại hướng đã được giao quyền và chọn trong D-007/D-008; chỉ giải quyết những chi tiết chưa xác định.

## Hồ sơ sau review

Bản review được lưu trong `reviews/`. Các đề nghị thay đổi protocol/evaluation được ghi mới ở **D-012 PROVISIONAL**, chưa thay D-011 và chưa sửa các notes/LaTeX gốc. Không có lab run, dataset lock, measurement hoặc kết quả cải thiện nào được tạo trong lần review này.
