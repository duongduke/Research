# Bảng báo cáo tiến độ hàng tuần — RQ-C1 (12 tuần)

> Đề tài: Đánh giá CVE có áp dụng cho một triển khai web cụ thể hay không, bằng cách
> hợp nhất bằng chứng từ 4 nguồn (CPE / NVD / vendor-advisory / HTTP-version) →
> kết luận Applicable / NotApplicable / Unknown (mức "áp dụng", không phải mức "đã khai thác"),
> so sánh với 4 phương pháp đơn nguồn. Sản phẩm là **phần mềm**.
>
> Ghi chú khi dán vào sheet:
> - Cột **Nhận xét GVHD** / **Đánh giá GV** để trống; **Ngày nộp** để trống tới khi thực nộp.
> - Đường dẫn trong "Kết quả / sản phẩm" là **đường dẫn cục bộ** (chưa đưa lên Git).
> - Tuần 11–12 (viết quyển + nộp) là **kế hoạch**, chưa thực hiện.

## Bảng tiến độ

| Tuần | Từ ngày | Đến ngày | Công việc đã thực hiện | Kết quả / sản phẩm (minh chứng, link) | Kế hoạch tuần tới | Khó khăn, vướng mắc | Kiến nghị, đề xuất | Ngày nộp | Nhận xét GVHD | Đánh giá GV |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 12/10 | 18/10 | **Đăng ký đề tài, đề cương (T1):** hoàn thiện đề cương ĐATN được GVHD duyệt; chốt hướng nghiên cứu (hợp nhất 4 nguồn bằng chứng → mức "áp dụng") và danh sách 30 CVE ban đầu. | `research/de-cuong-do-an/de-cuong-do-an.pdf`; `notes/cve-verification-2026-10-07.md` | Khảo sát tài liệu liên quan. | Chọn hướng + phạm vi "mức áp dụng" giữa 3 hướng đề xuất. |  |  |  |  |
| 2 | 19/10 | 25/10 | **Tổng quan (T2):** đọc 2 bài báo gốc (VAVI, Vuln2Action) + ghi chú; khảo sát các hướng hợp nhất bằng chứng. | `notes/Doc_hai_bai_RQ_C1_2026-09-30.md`; `notes/literature-evidence-fusion-2026-10-10.md` | Xác định đóng góp; dự thảo quy tắc gán nhãn + luật hợp nhất. |  |  |  |  |  |
| 3 | 26/10 | 01/11 | **Tổng quan (T3):** xác định đóng góp (xử lý trùng lặp giữa các nguồn + ưu tiên nguồn quan trọng); dự thảo quy tắc gán nhãn chuẩn và luật hợp nhất bằng chứng. | `notes/ground-truth-protocol.md`; `notes/fusion-design-2026-10-10.md` | Thiết kế chi tiết: luật hợp nhất, bộ đánh giá, mô tả thu thập tín hiệu. |  |  |  |  |  |
| 4 | 02/11 | 08/11 | **Thiết kế (T4):** chốt luật hợp nhất bằng chứng (kiểm tra bản bị ảnh hưởng + từng điều kiện của đường tấn công; ưu tiên nguồn advisory khi mâu thuẫn); chốt bộ đánh giá (precision / recall / F1 + mức bao phủ); viết mô tả thu thập tín hiệu theo từng CVE. | `notes/collector-mapping-spec-2026-10-11.md`; `context/DECISIONS.md` | Mô tả hiện thực; đóng băng luật + dữ liệu công khai. | Quy tắc gán nhãn chuẩn đang chờ góp ý, chưa chốt. | Đề nghị GVHD/TA góp ý về quy tắc gán nhãn chuẩn. |  |  |  |
| 5 | 09/11 | 15/11 | **Thiết kế (T5):** hoàn thiện quy tắc gán nhãn chuẩn và chốt theo góp ý của GVHD/TA; viết mô tả hiện thực 5 phương pháp; đóng băng luật + dữ liệu công khai. | `notes/ground-truth-protocol.md`; `notes/method-implementation-spec-2026-10-15.md`; `data/public-snapshot/` | Bắt đầu hiện thực 5 phương pháp. |  |  |  |  |  |
| 6 | 16/11 | 22/11 | **Hiện thực (T6):** code 5 phương pháp (CPE / NVD / advisory / HTTP-version + hợp nhất) + công cụ đánh giá + bộ so sánh phiên bản. | `experiments/methods/` — `methods.py`, `harness.py`, `metrics.py`, `versioncmp.py`, `build_inputs.py` | Điền + khóa bảng thu thập tín hiệu; dựng môi trường sandbox. |  |  |  |  |  |
| 7 | 23/11 | 29/11 | **Hiện thực (T7):** điền + khóa bảng thu thập tín hiệu cho 30 CVE; dựng môi trường sandbox tái hiện 30 CVE (chỉ chạy nội bộ). | `notes/collector-mapping-30cve.md`; `experiments/26cve/registry.md` | Hoàn thiện bộ kiểm thử; chạy đánh giá so sánh. |  |  |  |  |  |
| 8 | 30/11 | 06/12 | **Hiện thực (T8):** hoàn thiện bộ kiểm thử tổng hợp (193/193 pass); chạy đánh giá vòng V1 → V2; sửa lỗi hiện thực và thu/kiểm chứng thêm tín hiệu điều kiện. | `experiments/methods/fixture/`; `output/benchmark/`; `output/benchmark-v2/` | Bổ sung 2 CVE; đóng băng bảng 32 CVE; chạy vòng V3. | Vòng V1 phương pháp hợp nhất chưa kết luận được ca nào (thiếu tín hiệu điều kiện). |  |  |  |  |
| 9 | 07/12 | 13/12 | **Hiện thực (T9):** bổ sung 2 CVE (Joomla CVE-2023-23752, WordPress Backup Migration CVE-2023-6553) kèm tái hiện; đóng băng bảng 32 CVE; chạy đánh giá V3. | `experiments/topup-2026-10-17/cases/`; `data/public-snapshot-2026-10-17/`; `output/benchmark-v3/` | Phân tích kết quả; đo giới hạn quan sát qua HTTP. | 2 ca XSS (CVE-2023-5631, CVE-2019-6341) chưa kết luận được. |  |  |  |  |
| 10 | 14/12 | 20/12 | **Thực nghiệm, đánh giá (T10):** phân tích các ca bị bỏ sót (đo giới hạn quan sát qua HTTP); diễn giải kết quả V3 (phương pháp hợp nhất precision 1.0 / recall 0.194 so với baseline 0.419); soạn báo cáo tiến độ + câu hỏi. | `notes/u_a-breakdown-2026-10-19.md`; `notes/bao-cao-tien-do-2026-10-19.md`; `research/bao-cao-tien-do-2026-10-19/bao-cao-tien-do-2026-10-19.pdf` | Đưa toàn bộ lên Git; bắt đầu viết chương Tổng quan + Phương pháp. | Phương pháp hợp nhất có recall thấp hơn baseline — do giới hạn quan sát của mức "áp dụng", không phải lỗi hiện thực. |  |  |  |  |
| 11 | 21/12 | 27/12 | *(kế hoạch)* |  | **Viết quyển ĐATN (T11):** viết các chương Tổng quan, Phương pháp, Hiện thực, Kết quả; gửi GVHD góp ý và chỉnh sửa. |  |  |  |  |  |
| 12 | 28/12 | 30/12 | *(kế hoạch)* |  | **Hoàn thiện, nộp quyển, bảo vệ (T12):** quyển chính thức, slide bảo vệ, video demo; nộp đúng hạn. |  |  |  |  |  |

## Ghi chú nguồn (không dán vào sheet)

- Nội dung công việc và kết quả ở tuần 1–10 là **thực** (có file minh chứng; số liệu V3 từ `output/benchmark-v3/metrics.json`, N=67). Tuần 11–12 (viết quyển + nộp/bảo vệ) là **kế hoạch**, chưa thực hiện.
- Phân bố theo tuần được **dàn theo thứ tự pha và hạn của lộ trình** (T1 18/10 → T2-T3 01/11 → T4-T5 15/11 → T6-T9 13/12 → T10 20/12 → T11 27/12 → T12 30/12), phục vụ điền form; thực tế triển khai gọn hơn về thời gian.
- Không có phần trăm, không có nhận xét/đánh giá của GVHD, không có link ngoài workspace.
