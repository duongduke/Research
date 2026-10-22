# Khảo sát tài liệu: kết hợp bằng chứng cho đánh giá khả năng áp dụng CVE lên mục tiêu web

Ngày: 2026-10-10. Phạm vi: khảo sát ngắn phục vụ D-017 (thiết kế "fusion tối ưu" cho
hướng 3 / mức 2). Mục tiêu trả lời 4 câu hỏi: (1) độ tin cậy / trọng số nguồn, (2) dư
thừa / tương quan giữa nguồn, (3) độ quan trọng của thông tin, (4) xử lý mâu thuẫn.

> Quy ước mức tin cậy (tuân theo quy tắc "chỉ nguồn thật"):
> - **verified** = đã mở và đọc nội dung/abstract trong phiên này.
> - **verified (abstract qua arXiv API)** = đã mở metadata + abstract qua arXiv API.
> - **candidate** = chỉ thấy tên/trích dẫn qua nguồn thứ cấp, chưa mở đọc nội dung gốc.
> Mọi tiêu đề/tác giả/năm/URL dưới đây đều lấy trực tiếp từ trang/abstract đã mở, không bịa.

---

## 1. Tóm tắt (bài toán + phát hiện chính)

Bài toán của đồ án: với một cặp (triển khai web cụ thể × CVE), quyết định
**Applicable / Not Applicable / Unknown** bằng cách kết hợp 4 nguồn bằng chứng (CPE,
NVD, vendor advisory, quan sát HTTP), trong đó phải xử lý dư thừa (dải phiên bản bị ảnh
hưởng lặp lại ở CPE/NVD/advisory) và độ quan trọng (precondition trong advisory quan
trọng hơn dải CPE cho quyết định mức 2).

Phát hiện chính của khảo sát:

1. **Phần lớn công trình "fusion/ưu tiên CVE" hiện có nhắm vào *prioritization* (xếp
   hạng nên vá CVE nào) hoặc *affected-version identification* (phiên bản nào bị ảnh
   hưởng), chứ không nhắm vào *applicability trên một triển khai cụ thể*. Ví dụ EPSS
   tự khai rõ là "population-level, không phải phát biểu về một instance cụ thể".
2. **Công trình gần nhất về "fusion bằng chứng cho CVE"** là ThreatLens (2026, CIKM):
   fusion nhiều tín hiệu + học yếu từ CISA KEV + đánh giá forward-in-time, nhưng vẫn là
   *ranking*, không có quan sát HTTP của một mục tiêu cụ thể, không ra nhãn
   Applicable/Not/Unknown cho một triển khai.
3. **Các kỹ thuật chuyển dùng được**: (a) học trọng số nguồn bằng gradient boosting —
   an toàn trước dư thừa/tương quan (EPSS); (b) Dempster–Shafer với discounting độ tin
   cậy nguồn + khối xung đột (M-STAR, các mô hình trust DS); (c) decision-tree / chuỗi
   hai giai đoạn thay vì cộng dồn naive (SSVC, Vulnerability Management Chaining); (d)
   ngữ nghĩa product-status của VEX/CSAF (known_affected / known_not_affected +
   precondition) — gần đúng với mức 2 của đồ án.
4. **Cảnh báo trực tiếp về "kết hợp nguồn"**: EPSS gọi việc nhân EPSS×CVSS là "score
   laundering" (sai về thang đo); việc cộng xác suất giả định độc lập
   (1−∏(1−p)) cũng được EPSS nêu rõ là *giả định*, chính là chỗ dư thừa/tương quan phải
   xử lý.
5. **Khoảng trống**: chưa có công trình nào làm fusion *được đánh giá* (có ground truth
   từ tái tạo lab) cho quyết định applicability trên một triển khai, kết hợp CPE/NVD/
   advisory/HTTP, với khử dư thừa tường minh, trọng số độ quan trọng, xử lý mâu thuẫn và
   đầu ra Unknown có ngưỡng bằng chứng rõ ràng.

---

## 2. Các phương pháp / công trình liên quan

Ký hiệu xử lý: R = redundancy (dư thừa), W = trọng số/độ tin cậy, I = độ quan trọng,
C = xung đột.

### 2.1 Hệ thống chấm điểm / chuẩn (primary sources)

| Tên | Năm | Ý tưởng | R / W / I / C | URL | Mức tin cậy |
|---|---|---|---|---|---|
| EPSS (FIRST.org) | 2019–nay | Ước lượng xác suất CVE bị khai thác trong 30 ngày; ~2850 đặc trưng từ 5 nhóm nguồn; XGBoost + PU learning + calibration; đo coverage/effort/efficiency | W: học trọng số theo dữ liệu, không giả định nguồn nào đáng tin hơn; R: mỗi domain nguồn là 1 feature riêng, GBDT xử lý tương quan không cộng trùng; I: feature importance (tuổi CVE mạnh nhất); C: hướng dẫn "KEV (đã bị khai thác) ưu tiên hơn điểm EPSS" | https://www.first.org/epss/ ; /how-it-works ; /using-epss ; /research | verified |
| SSVC (CERT/CC, CMU SEI) | 2019/2020 | Cây quyết định phân loại hành động theo stakeholder; các "decision point" mô-đun, thay thế một cỡ cho tất cả | I: cấu trúc cây mã hóa thứ tự ưu tiên; C: đầu ra rời rạc theo nhánh, không trộn số | https://github.com/CERTCC/SSVC ; https://certcc.github.io/SSVC/ | verified (README + citation) |
| CSAF 2.0 (OASIS), profile VEX | 2022/2024 | Chuẩn trao đổi advisory; VEX cho phép vendor tuyên bố trạng thái sản phẩm (known_affected / known_not_affected / under_investigation / fixed) kèm precondition | I: product status + precondition là thông tin quyết định applicability; R: một nguồn có thẩm quyền duy nhất (vendor) — không có fusion | https://docs.oasis-open.org/csaf/csaf/v2.0/errata01/os/csaf-v2.0-errata01-os.html | verified |
| CPE Naming 2.3 (NIST IR 7695) | 2011 | Cấu trúc tên CPE cho phép mô tả product/version; nền tảng cho "CPE match criteria" (dải version) trong NVD | R: dải version này bị lặp ở CPE/NVD/advisory → nguồn gốc dư thừa cần khử | https://csrc.nist.gov/pubs/ir/7695/final (doi:10.6028/NIST.IR.7695) | verified |
| CISA KEV (Known Exploited Vulnerabilities) | 2021–nay | Danh mục CVE "bị khai thác trên thực tế" (đã xác nhận); tín hiệu exploitation mạnh, dùng làm nhãn yếu/ưu tiên | I: exploitation xác nhận là tín hiệu ưu tiên cao; C: khác bản chất với EPSS (lịch sử vs dự báo) | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | candidate (trang gốc 403; vai trò/nội dung xác nhận qua các trang EPSS đã mở) |

### 2.2 Công trình học thuật

| Tên (rút gọn) | Năm | Ý tưởng | R / W / I / C | URL | Mức tin cậy |
|---|---|---|---|---|---|
| "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights" (Jacobs, Romanosky, Suciu, Edwards, Sarabi) | 2023 | Mô tả EPSS v3; học trọng số đặc trưng theo dữ liệu | W/R: nguồn là feature, học trọng số | https://arxiv.org/abs/2302.14172 | verified (abstract qua arXiv API) |
| "ThreatLens: Evidence-Guided Ranking of High-Priority CVEs" (Motamedi Sedeh, Shahrivar, Qureshi, Devjiani, Tayebi) | 2026 | Fusion nhiều tín hiệu (CVSS/EPSS/advisory/exploit) để *xếp hạng* CVE; học yếu từ KEV; đánh giá forward-in-time, CVE-disjoint | W: fusion có trọng số (vượt baseline rule-based); R: chỉ dùng bằng chứng "cutoff-valid" tránh rò tương lai; I: tín hiệu nào quan trọng do mô hình học | https://arxiv.org/abs/2608.22306 (CIKM 2026) | verified (abstract qua arXiv API) |
| "A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges" (Jiang, Oo, Meng, Lim, Sikdar) | 2025 | SLR 82 nghiên cứu; taxonomy gồm severity, exploitability, contextual, predictive, **aggregation methods** | W/I/C: liệt kê các cách tổng hợp (aggregation) là một lớp riêng | https://arxiv.org/abs/2502.11070 | verified (abstract qua arXiv API) |
| "Vulnerability Management Chaining" (Shimizu, Hashimoto) | 2026 | Khung 2 giai đoạn: lọc theo threat (KEV/EPSS≥0.088) rồi severity (CVSS≥7.0); cây quyết định | R: chuỗi (sequencing) thay vì cộng điểm, tránh đếm trùng; I: threat trước severity | https://arxiv.org/abs/2506.01220 (IEEE Access 2026) | verified (abstract qua arXiv API) |
| "When Cyber Scoring Systems Diverge: An Empirical Comparison" (Hellsten et al.) | 2026 | Đo mức bất đồng CVSS/EPSS/SSVC/IronMiner trên cùng hiện trường OT | C: chứng minh các hệ chấm mâu thuẫn nhau nhiều; đề xuất composite/hybrid | https://arxiv.org/abs/2609.37217 | verified (abstract qua arXiv API) |
| "Conflicting Scores, Confusing Signals: An Empirical Study of Vulnerability Scoring Systems" (Koscinski, Nelson, Okutan, Falso, Mirakhorli) | 2025 | Nghiên cứu thực nghiệm về hệ chấm điểm mâu thuẫn | C | https://doi.org/10.1145/3719027.3765210 (CCS '25) | candidate (thấy trên EPSS research page, chưa mở) |
| "Expected Exploitability" (Suciu, Nelson, Lyu, Bao, Dumitraș) | 2022 | Dự đoán exploit *chức năng* sẽ hình thành | W/I (exploit prediction) | https://www.usenix.org/conference/usenixsecurity22/presentation/suciu | candidate (trên EPSS research page) |
| "Improving Vulnerability Remediation Through Better Exploit Prediction" (Jacobs, Romanosky, Adjerid, Baker) | 2020 | Tiền thân EPSS; so sánh chiến lược vá theo coverage/efficiency | W/I | https://doi.org/10.1093/cybsec/tyaa015 | candidate (trên EPSS research page) |
| "Exploit Prediction Scoring System (EPSS)" (Jacobs, Romanosky, Edwards, Roytman, Adjerid) | 2021 | Mô tả EPSS v1 (DTRAP) | W/I | https://dl.acm.org/doi/10.1145/3436242 ; arXiv:1908.04856 | candidate (trên EPSS research page) |
| "Likely Exploited Vulnerabilities" (Mell, Spring) | 2025 | Metric xác suất bị khai thác của NIST (CSWP 41) | W/I | https://doi.org/10.6028/NIST.CSWP.41 | candidate (trên EPSS research page) |
| "GitHub Engagement Signals for CVE Prioritization (GPM)" (Akhoundali, Rietveld, Gadyatskaya) | 2026 | Metric độ phổ biến exploit trên GitHub; đã tích hợp vào EPSS v5 | W/I: thêm nguồn tín hiệu mới | https://arxiv.org/abs/2609.31004 | verified (abstract qua arXiv API) |
| "How Reliable Are NVD CWE Labels?" (Nong, Du, Behravan, Cai) | 2026 | Đo độ tin cậy nhãn CWE trong NVD: chỉ ~49.7% khớp chính xác, 3.63% sai | W: bằng chứng NVD không phải nguồn "luôn đúng" → cần trọng số nguồn | https://arxiv.org/abs/2608.21977 | verified (abstract qua arXiv API) |
| "HARP: Hierarchical Adaptive Ranking with Preference-Adaptive Fusion" (Liu et al.) | 2026 | Xếp hạng CVE theo truy vấn; fusion nhiều view với trọng số fitted từ support | W: view-fusion weights | https://arxiv.org/abs/2608.19430 | verified (abstract qua arXiv API) |
| "Bridging the Gap Between Security Metrics and KRIs" (Sherif, Yevseyeva, Basto-Fernandes, Cook) | 2026 | KRI tổng hợp threat × impact × exposure; ablation so EPSS/CVSS | I: decomposition expected-loss; W: ablation từng nguồn | https://arxiv.org/abs/2603.12450 | verified (abstract qua arXiv API) |
| "PECR" (Alam) | 2026 | 9 yếu tố chuẩn hóa + báo confidence/interval riêng; stress-test trọng số Dirichlet | W/I: tách điểm khỏi khoảng tin cậy; R: phát hiện "evidence-limited" khi thiếu ô | https://arxiv.org/abs/2608.03110 | verified (abstract qua arXiv API) |
| "Vulnerability Prioritization: An Offensive Security Approach" (Bulut, Adebayo, Sow, Ocepek) | 2022 | Ưu tiên theo góc nhìn pentester | I (thay CVSS) | https://arxiv.org/abs/2206.11182 | verified (abstract qua arXiv API) |

### 2.3 Dempster–Shafer / Bayesian fusion + độ tin cậy nguồn

| Tên | Năm | Ý tưởng | R / W / I / C | URL | Mức tin cậy |
|---|---|---|---|---|---|
| "M-STAR: A Modular, Evidence-based Software Trustworthiness Framework" (Alexopoulos, Habib, Schulz, Mühlhäuser) | 2018 | Đánh giá độ tin cậy phần mềm (Debian) từ lịch sử lỗ hổng + thuộc tính mã, dùng Bayesian + DS belief | W: kết hợp nhiều bằng chứng với DS; R: modular; C: DS có khối xung đột | https://arxiv.org/abs/1801.05764 | verified (abstract qua arXiv API) |
| "Quantifying IIoT Sensor Node Criticality by Fusing its Data Criticality and Security Vulnerability" (Sen, Karmakar, Pang) | 2026 | Dùng DS để fusion "data criticality" + "security vulnerability" (CVSS 4.0 vs 3.1) | W/C: DS fusion; cho thấy CVSS 4.0 đổi thứ hạng so với 3.1 | https://arxiv.org/abs/2609.09807 | verified (abstract qua arXiv API) |
| "A non-biased trust model for wireless mesh networks" (Tan, Ma, Labiod, Chong, Zhang) | 2016/2017 | DS + dissimilarity test để xử lý xung đột giữa các nguồn khuyến nghị | C: đo mức xung đột rồi gán belief; W: discounting | https://arxiv.org/abs/1712.09862 (doi:10.1002/dac.3200) | verified (abstract qua arXiv API) |
| "Credible fusion of evidence in distributed system subject to cyberattacks" (Ma, Liang) | 2024 | Fusion bằng chứng chống xung đột cao + loại attacker | C: "conditionalized credibility" tránh kết quả phản trực giác khi xung đột cao; W | https://arxiv.org/abs/2412.04496 | verified (abstract qua arXiv API) |
| Dempster–Shafer / Shafer "A Mathematical Theory of Evidence" | 1967/1976 | Lý thuyết bằng chứng: belief/plausibility, luật kết hợp, discounting độ tin cậy nguồn | W (discounting), C (khối xung đột K) | (sách Princeton UP, 1976) | candidate (kinh điển, trích dẫn gián tiếp qua M-STAR) |
| Zadeh's counterexample; Yager's rule; Murphy averaging | 1979–2000 | Phê phán luật Dempster khi bằng chứng xung đột cao; các luật thay thế | C | (canonical) | candidate (Yager's rule được nhắc trong IPEK arXiv:2604.07532) |

### 2.4 Hai bài khởi điểm của đồ án (đã đọc trong workspace)

| Tên | Năm | Ý tưởng | URL | Mức tin cậy |
|---|---|---|---|---|
| "Vulnerability-Affected Versions Identification: How Far Are We?" (Xingchu Chen et al.) | 2025 | So sánh 12 công cụ xác định tập phiên bản bị ảnh hưởng từ mã nguồn; có **ensemble voting** tăng F1 | https://arxiv.org/abs/2509.03876 (ASE 2025) | verified (đã đọc, xem `notes/Doc_hai_bai_RQ_C1_2026-09-30.md`) |
| "Vuln2Action: An LLM-based framework for generating vulnerability reproduction steps and mapping exploits" (Shalini Kumari, Geeta Yadav) | 2026 | Sinh bước tái tạo + ánh xạ exploit bằng LLM; hỗ trợ dựng giả thuyết reproduction | https://doi.org/10.1016/j.jisa.2026.104420 (JISA 99) | verified (đã đọc) |

---

## 3. Kỹ thuật tổng hợp áp dụng được cho đồ án

### 3.1 Khử dư thừa (redundancy) — trả lời Q2

- **Mô hình hóa "dải version bị ảnh hưởng" như một khẳng định duy nhất, không đếm 3 lần.**
  CPE/NVD/advisory đều lặp lại cùng dải version (NVD chép advisory, CPE lấy từ advisory).
  → Gom thành *một* nút bằng chứng "affected range" với nguồn gốc (provenance) ghi rõ,
  hoặc khử trùng bằng cách chỉ lấy giao/hợp một lần. Đây là đúng mối lo của D-017 và
  review R6.
- **Không cộng dồn naive.** EPSS cảnh báo "score laundering" (nhân EPSS×CVSS vô nghĩa vì
  khác thang đo); việc kết hợp xác suất 1−∏(1−p) chỉ đúng nếu *độc lập* — chính là giả
  định bị phá vỡ khi các nguồn tương quan.
- **Chuỗi hai giai đoạn thay vì tổng trọng số.** "Vulnerability Management Chaining" dùng
  sequencing (threat trước, severity sau) để tránh đếm trùng. Đồ án có thể dùng cấu trúc
  tương tự: (1) xác định affected range từ nguồn công khai (khử trùng), (2) kiểm
  precondition từ advisory + HTTP.
- **GBDT / ensemble học trọng số** (EPSS) xử lý feature tương quan tự nhiên (cây chỉ split
  một feature tại mỗi nút, không cộng tín hiệu trùng) — phù hợp nếu muốn học trọng số từ
  benchmark thay vì đặt tay.

### 3.2 Trọng số / độ tin cậy nguồn (Q1)

- **DS discounting** (Shafer): mỗi nguồn có hệ số tin cậy α∈[0,1], belief được chiết khấu
  trước khi kết hợp — cách chuẩn để mô hình "nguồn nào đáng tin hơn".
- **Học trọng số theo dữ liệu** (EPSS, ThreatLens, HARP): không giả định trọng số, để
  mô hình/benchmark xác định. Với đồ án có ground truth từ reproduction, có thể *học/điều
  chỉnh* trọng số hoặc ít nhất *báo cáo* độ nhạy trọng số (như PECR làm với Dirichlet).
- **NVD không mặc định "đúng"**: Nong et al. (2026) cho thấy nhãn CWE trong NVD chỉ ~50%
  khớp; advisory của vendor thường là nguồn chính xác nhất cho precondition/affected range
  (VEX đặt thẩm quyền ở vendor). → trọng số: advisory > NVD ≈ CPE cho nội dung liên quan
  precondition; HTTP là bằng chứng *trạng thái sống*, khác bản chất với 3 nguồn dữ liệu.

### 3.3 Độ quan trọng của thông tin (Q3)

- **Tách tầng bằng chứng** (đồ án đã có ở D-017): precondition (advisory + HTTP) quyết định
  mức 2, còn dải version chỉ là điều kiện cần. SSVC/VEX mã hóa điều này bằng decision point
  và product status.
- **Ưu tiên tín hiệu xác nhận**: EPSS quy tắc "KEV (đã bị khai thác) ưu tiên hơn điểm" —
  tương đương "bằng chứng trực tiếp về trạng thái (HTTP, patch applied) ưu tiên hơn suy
  luận gián tiếp từ dải version".
- **Feature importance / ablation**: báo cáo ablation từng nguồn (KRI, D-016 của đồ án) để
  chứng minh nguồn nào đóng góp gì — đồ án đã định làm so sánh 4 nguồn đơn + fusion.

### 3.4 Xử lý mâu thuẫn (Q4)

- **DS khối xung đột K** đo mức mâu thuẫn; khi K cao, luật Dempster chuẩn cho kết quả phản
  trực giác (Zadeh counterexample) → dùng Yager's rule / Murphy averaging để giữ trạng thái
  "revisable" thay vì kết luận cực đoan.
- **Precedence thay vì trung bình**: khi hai nguồn khác bản chất mâu thuẫn (VD: NVD nói
  affected nhưng HTTP cho thấy phiên bản đã backport patch — đúng ca nginx CVE-2021-23017
  của đồ án), luật "bằng chứng trực tiếp ưu tiên" (HTTP/advisory về fix) thắng dải CPE.
  Đây là trường hợp "fusion-wins" đồ án đã chủ ý đưa vào benchmark.
- **Báo "Unknown" có ngưỡng** thay vì ép chọn phe: khi mâu thuẫn chưa giải được hoặc thiếu
  bằng chứng quyết định, trả Unknown/abstention (đồ án đã có khái niệm Unknown; PECR dùng
  "evidence-limited" khi khoảng tin cậy cắt ngưỡng quyết định).

---

## 4. Khoảng trống (chỗ đồ án khác biệt / đóng góp)

1. **Đa số công trình "fusion CVE" là prioritization (xếp hạng), không phải applicability.**
   EPSS/ThreatLens/KRI/Chaining/HARP đều trả lời "nên ưu tiên vá CVE nào", không trả lời
   "CVE này có *áp dụng* cho triển khai này không" (Applicable/Not/Unknown).
2. **Không ai kết hợp *quan sát HTTP sống của một mục tiêu cụ thể* với nguồn dữ liệu công
   khai để quyết định applicability.** EPSS nói rõ nó "không biết gì về môi trường của
   bạn"; ba bước "presence/reachability/consequence" trong tài liệu EPSS chỉ là hướng dẫn,
   không phải thuật toán được đánh giá.
3. **Khử dư thừa tường minh cho bộ (CPE, NVD, advisory) chưa được ai đánh giá định lượng.**
   Việc "affected range lặp 3 lần" là mối lo đã được D-017/review R6 nêu, nhưng khảo sát
   không thấy công trình nào đo tác động của việc đếm trùng/triple-count lên kết luận.
4. **Chưa có fusion applicability nào được đánh giá bằng ground truth từ *tái tạo lab*
   (reproduction) với so sánh 4 nguồn đơn + fusion trên cùng benchmark** (đúng thiết kế
   D-016 của đồ án). ThreatLens học yếu từ KEV, không có reproduction; VAVI đo affected
   version, không đo applicability trên triển khai.
5. **Xử lý mâu thuẫn giữa "affected theo CPE" và "thực tế đã vá/backport" chưa thành bài
   toán được benchmark hóa.** Ca nginx CVE-2021-23017 của đồ án (CPE nói affected, HTTP
   thấy version bị ảnh hưởng, nhưng package Ubuntu đã backport fix → Not Applicable) là
   một trường hợp "fusion phải thắng nguồn đơn" mà khảo sát chưa thấy ai làm thành tiêu chí
   đánh giá.

→ **Đóng góp đề xuất**: một luật kết hợp *có nguyên tắc, được đánh giá* cho applicability
trên triển khai, gồm: (a) khử dư thừa affected-range qua 3 nguồn dữ liệu, (b) trọng số
tầng (precondition > affected range) + trọng số nguồn (advisory > NVD/CPE; HTTP là bằng
chứng trực tiếp), (c) xử lý mâu thuẫn bằng precedence + khối xung đột, (d) đầu ra
Applicable/Not/Unknown có ngưỡng bằng chứng rõ, (e) đánh giá so 4 nguồn đơn + fusion trên
cùng ground truth reproduction (≥30 CVE).

---

## 5. Danh sách nguồn đã đọc (kèm URL)

**Mở trực tiếp (verified):**
1. FIRST EPSS — https://www.first.org/epss/
2. FIRST EPSS "How EPSS Works" — https://www.first.org/epss/how-it-works
3. FIRST EPSS "Using EPSS" — https://www.first.org/epss/using-epss
4. FIRST EPSS "Research" — https://www.first.org/epss/research
5. CERT/CC SSVC (GitHub) — https://github.com/CERTCC/SSVC
6. OASIS CSAF 2.0 Errata 01 — https://docs.oasis-open.org/csaf/csaf/v2.0/errata01/os/csaf-v2.0-errata01-os.html
7. NIST IR 7695 (CPE Naming 2.3) — https://csrc.nist.gov/pubs/ir/7695/final
8. arXiv API: "vulnerability prioritization" (15 kết quả) — http://export.arxiv.org/api/query?search_query=all:%22vulnerability%20prioritization%22
9. arXiv API: "evidence fusion" AND security — http://export.arxiv.org/api/query?search_query=all:%22evidence%20fusion%22%20AND%20all:security
10. arXiv API: "Dempster-Shafer" AND vulnerability — http://export.arxiv.org/api/query?search_query=all:%22Dempster-Shafer%22%20AND%20all:vulnerability
11. arXiv API: "CPE matching" / "CVE applicability" (không có kết quả liên quan) — đã tra

**Abstract đã đọc qua arXiv API (verified-abstract):** 2302.14172, 2608.22306, 2502.11070,
2506.01220, 2609.37217, 2609.31004, 2608.21977, 2608.19430, 2603.12450, 2608.03110,
2206.11182, 1801.05764, 2609.09807, 1712.09862, 2412.04496.

**Candidate (thấy trên EPSS Research page, chưa mở nội dung gốc):** Jacobs et al. 2021
(DTRAP), Jacobs et al. 2020 (J.Cybsec), Suciu et al. 2022 (USENIX), Iannone et al. 2024
(TOSEM), Mahbub et al. 2024 (DTRAP), Parla 2024 (arXiv:2411.02618), Koscinski et al. 2025
(CCS'25), Mell & Spring 2025 (NIST CSWP 41), Ravalico et al. 2025 (SSRN).

**Candidate (kinh điển, trích dẫn gián tiếp):** Shafer 1976; Dempster 1967; Zadeh
counterexample; Yager's rule / Murphy averaging.

**Không truy cập được (403):** trang CISA KEV và các trang cisa.gov khác (bị chặn bot);
chưa mở được nguồn gốc KEV, chỉ xác nhận qua nguồn thứ cấp.

---

## Ghi chú kèm (không phải kết luận)

- Web search tích hợp trả "No search results" trong phiên này; toàn bộ thu thập bằng
  webfetch trực tiếp + arXiv API. Vì vậy danh sách thiên về các nguồn có URL ổn định
  (FIRST, OASIS, NIST, arXiv); khả năng bỏ sót bài hội nghị vendor blog là có.
- Các con số trích từ abstract là của tác giả bài báo; chưa kiểm chứng chéo số liệu.
- Chưa đụng tới hướng "web fingerprinting" (nhận diện version qua HTTP) vì đó là hướng 1,
  ngoài phạm vi khảo sát fusion này.
