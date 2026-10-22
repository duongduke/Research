# Tổng hợp — Hướng nghiên cứu & Phương pháp nghiên cứu

> Ngày: 04/10/2026. Đây là bản **tổng hợp trao đổi** (working notes), không phải tài liệu
> chính thức gửi trợ giảng (tài liệu gửi ở `research/plan-so-bo.pdf`).
> Ký hiệu: **[CHỐT]** = đã xác định; **[GIẢ ĐỊNH]** = ta đang dùng nhưng chưa được trợ giảng xác nhận.

---

## 1. Đề tài (đã rõ)

- **Tên:** RQ-C1 — *Evidence-based CVE Applicability*.
- **Câu hỏi nghiên cứu gốc:**
  > "Can multiple sources of evidence improve the accuracy of determining whether a CVE actually applies to a detected product/version?"

- **Pipeline chính thức:**
  `input (product + version)` → thu bằng chứng (CVE, CPE, advisory, version history, patch, source/binary) → **evidence-fusion model** → `Applicable / Not Applicable / Unknown` → đánh giá accuracy, precision, recall, false mapping.

- **[CHỐT]** Miền áp dụng = **web interface** (bác OpenSSH / host scanning).

## 2. Ý trợ giảng — 3 hướng map vào pipeline

Trợ giảng xác nhận hiểu biết cơ bản *"Từ CVE khớp tên phần mềm hoặc phiên bản"* là đúng, rồi cho 3 hướng theo độ khó:

| Hướng | Nội dung | Là phần nào của pipeline |
|---|---|---|
| 1 (dễ) | Xác định version/range chính xác nhất (khi WAF/web ẩn version) | **Input** (detected product + version) |
| 2 (trung bình) | Ưu tiên CVE (khớp 100 CVE → chọn 10 ưu tiên) | **Đầu ra sau** (ranking) |
| 3 (khó) | Validate CVE khả thi **không cần khai thác trực tiếp** | **Lõi** (Applicable/Not/Unknown) |

**Đọc hiểu ý trợ giảng:** *"cách cơ bản em hiểu là đúng rồi"* = đúng nhưng còn nông; 3 hướng = 3 mức sâu của CÙNG bài toán; anh đưa **menu** để sinh viên tự chọn + tự biện minh dựa trên SOTA (2 bài báo). → **Hướng 3 gần như chính là đề tài gốc.**

## 3. Hướng đã chọn [GIẢ ĐỊNH — cần xác nhận]

- **Chọn hướng 3** (= đề tài gốc), thu hẹp scope để khả thi 3 tháng.
- Câu RQ cụ thể:
  > "So với dùng một nguồn bằng chứng lẻ (baseline), kết hợp nhiều nguồn có làm tăng accuracy/precision/recall và giảm false mapping hay không, và tăng/giảm bao nhiêu (đo trên benchmark có nhãn chuẩn độc lập)?"

## 4. Phương pháp nghiên cứu = thí nghiệm so sánh có đối chứng

**Phương pháp = chuỗi việc ta làm để trả lời RQ.** Cấu trúc RQ sinh ra cấu trúc phương pháp:

| Thành phần RQ | Biến trong thí nghiệm |
|---|---|
| "một nguồn lẻ vs kết hợp nhiều nguồn" | **Biến độc lập**: chiến lược bằng chứng (đơn nguồn / fusion) |
| "tăng accuracy/precision/recall, giảm false mapping" | **Biến phụ thuộc**: các metric |
| "đo trên benchmark có nhãn chuẩn độc lập" | **Điều kiện đối chứng**: cùng dataset, cùng nhãn, cùng input |

**6 bước:**

1. **Xây benchmark** (nhãn chuẩn độc lập): tập bộ ba `(product, version, CVE)` → nhãn {Applicable / Not / Unknown}.
2. **Trích xuất bằng chứng** (đầu vào chung cho cả 2 cách): CPE, advisory, version history, patch.
3. **Xây baseline đơn nguồn** (vd CPE-only) → 3 lớp.
4. **Xây phương pháp đề xuất (fusion)** (rule-based/voting) → 3 lớp.
5. **Chạy cả 2 trên CÙNG benchmark, đo** accuracy/precision/recall/false mapping → tính chênh lệch %.
6. **Phân tích** (fusion thắng/thua ở đâu, vì sao) + threats to validity.

## 5. Vị trí của reproduce lab

- **[CHỐT]** Lab nằm ở **Bước 1 (xây benchmark)**, nhánh tạo nhãn chuẩn — **không phải một bước trong pipeline phương pháp**.
- **Bước 1 có 2 nhánh gán nhãn:**
  - (a) *Đa số ca:* advisory chính thức + phân tích patch, gán theo protocol độc lập (2 người + phân xử).
  - (b) *Tập con ca:* **reproduce lab** (dựng affected/fixed trong sandbox, chạy PoC) → xác nhận cứng nhãn.
- Vì sao không "circular": phương pháp chỉ dùng **bằng chứng công khai**; lab là **nguồn ground truth độc lập** (không đưa vào fusion).

## 6. Ranh giới khái niệm (3 mức, dễ nhầm)

| Mức | Nghĩa | Ai xác định |
|---|---|---|
| 1. Affected version | Version nằm trong dải affected | CPE/advisory |
| 2. **Applicable** | Lỗi thực sự nằm trong version này (mã lỗi có mặt) | **Fusion (phương pháp)** |
| 3. Exploitable / "khả thi" | Thực sự khai thác được (feature bật, reachable, không mitigation) | **Reproduce lab** |

- [GIẢ ĐỊNH] Trợ giảng dùng từ "khả thi" — cần hỏi là **Applicable** (mức 2) hay **Exploitable** (mức 3).

## 7. Định nghĩa "web interface" (có nguồn)

- **Không có chuẩn duy nhất** định nghĩa "web interface" liệt kê sẵn thành phần.
- Neo theo nguồn có thật:
  - *Vulnerability* — NIST SP 800-30 (CNSSI 4009); OWASP.
  - *System* — OWASP: "operating systems, web server, application frameworks and related infrastructure".
  - *"publicly exposed"* — CISA BOD 26-04: "accessible to unauthenticated or untrusted entities via public networks".
  - *"web management interface"* — CISA BOD 23-02.
- **Operational scope của đồ án [GIẢ ĐỊNH, do tác giả chọn]:** web-facing target = phần mềm dùng HTTP(S), quan sát được từ mạng; 4 nhóm: (1) web server, (2) reverse proxy/WAF/gateway, (3) backend framework, (4) web app/CMS.

## 8. Chọn sản phẩm [ĐỀ XUẤT]

- **Apache HTTP Server** — chính, sâu, reproduce lab (đã có lab).
- **nginx (Ubuntu)** — thứ 2, kịch bản **distro backport** (nơi fusion thắng rõ).
- **Jenkins** (nếu kịp) — khác loại (web app), advisory chuẩn, tái tạo được.

## 9. Câu hỏi cần chốt với trợ giảng

1. Làm **trọn hướng 3** (= đề tài gốc, thu hẹp scope) hay được phép chọn hướng 1/2? [GIẢ ĐỊNH chính]
2. "web interface" rộng đến đâu — 4 nhóm trên, hay hẹp hơn (chỉ web server / web management interface)?
3. Ground truth "Applicable" lấy từ đâu — dữ liệu công khai (advisory/patch) hay có source/binary?
4. Reproduce lab là **bắt buộc / tùy chọn / ngoài phạm vi**?
5. "khả thi" = **Applicable** (mức 2) hay **Exploitable** (mức 3)?

## 10. Trạng thái hiện tại

- **[CHỐT]**: domain = web interface; đề tài = Evidence-based CVE Applicability; phương pháp = thí nghiệm đối chứng (fusion vs đơn nguồn); lab = ground truth (Bước 1).
- **[GIẢ ĐỊNH]**: chọn hướng 3; phạm vi "web interface" 4 nhóm; "khả thi ≈ applicable"; sản phẩm Apache+nginx(+Jenkins).
- **Bước kế tiếp**: gửi trợ giảng để biến giả định → xác nhận (câu hỏi mục 9).

---

*Tham chiếu:* tài liệu chính thức `research/plan-so-bo.pdf` (7 mục + tài liệu tham khảo có nguồn); ghi chú đọc 2 bài báo `notes/Doc_hai_bai_RQ_C1_2026-09-30.md`.
