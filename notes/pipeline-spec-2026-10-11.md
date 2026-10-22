# Pipeline spec — 5 phương pháp + evaluation (bản nháp để duyệt)

> Ngày: 11/10/2026. Trạng thái: **ĐỀ XUẤT** (spec kiến trúc để giao engineer; chưa phải phương
> pháp đã duyệt). Liên kết: D-016 (4 nguồn + fusion), D-019 (rule chốt), D-026 (khóa rule +
> snapshot 2026-10-11 + metric), `notes/fusion-design-2026-10-10.md` (bộ rule),
> `notes/ground-truth-protocol.md` (nhãn chuẩn), `experiments/26cve/registry.md` (dữ liệu).

## 1. Mục tiêu

Cài đặt 5 phương pháp theo bộ rule đã khóa, chạy trên 30 ca, đối chiếu nhãn chuẩn, ra metric.
Tách bạch tuyệt đối **đầu vào phương pháp** (dữ liệu công khai snapshot + HTTP quan sát được)
khỏi **nhãn chuẩn** (ground truth trong lab) theo D-003.

## 2. Kiến trúc (4 khối)

```
[Snapshot collector] → [Evidence model] → [5 decision methods] → [Evaluator]
```

1. **Snapshot collector** — thu dữ liệu công khai (CPE / NVD / advisory) đóng băng tại
   **2026-10-11**, và đọc **HTTP observations** đã thu trong lab (không fetch lại mục tiêu thật).
2. **Evidence model** — chuẩn hóa thành các **assertion** (khẳng định kèm provenance + phạm vi),
   6 loại bằng chứng E1–E6 (theo fusion-design §2).
3. **5 decision methods** — mỗi method = một hàm `assertions → {Applicable, Not Applicable, Unknown}`,
   cài đúng rule ở fusion-design §3/§4.
4. **Evaluator** — đối chiếu prediction với nhãn chuẩn (registry), tính metric (D-026).

## 3. Data model — assertion

Mỗi assertion mô tả một khẳng định về một `(case, CVE)`:

| Field | Ý nghĩa |
|---|---|
| `case_id` | định danh case `(product, version/build, config, CVE)` |
| `cve_id` | CVE ID |
| `claim_type` | `E1` (dải affected) / `E2` (severity/loại) / `E3` (precondition) / `E4` (patch/backport) / `E5` (version suy ra từ HTTP) / `E6` (dấu hiệu feature/config) |
| `value` | `True` / `False` / `Unknown` (kèm lý do khi Unknown) |
| `provenance` | nguồn (CPE / NVD / advisory URL / HTTP response ref) + ngày snapshot |
| `scope` | product / build / nhánh mà khẳng định áp dụng |

**Khử dư thừa E1 (D-017):** các khẳng định "version ∈ dải affected" lặp ở CPE/NVD/advisory được
gom về **một assertion** với `provenance` là danh sách nguồn (không cộng 3 lần). Dải khác nhau
vẫn giữ riêng + ghi mâu thuẫn.

## 4. Đầu vào từng method (D-016)

| Method | Assertions được thấy |
|---|---|
| CPE-only | `E1(CPE)` + `E5` |
| NVD-only | `E1(NVD)` + `E2` + `E5` |
| Advisory-only | `E1(advisory)` + `E3` + `E4` + `E5` |
| HTTP version-string-only | `E5` + bảng dải affected tham chiếu chung (lookup table) |
| Fusion | `E1`–`E6` đầy đủ |

> CPE-only / NVD-only / HTTP-version-only dự kiến trùng nhau ở mức 1 (đều khớp version) — báo cáo
> sự trùng lặp này, không bịa khác biệt (D-018 R1).

## 5. Rule quyết định (tham chiếu, KHÔNG viết lại ở đây)

Luật đầy đủ nằm ở `notes/fusion-design-2026-10-10.md` (đã KHÓA theo D-026). Engineer cài đúng:
- 4 nguồn đơn (§3.1–§3.4), fusion 5 tầng + kết luận B/P_i (§4), precedence + mâu thuẫn (§4.1/§4.2).

## 6. Evaluator + metric

- Nhãn chuẩn: đọc từ `experiments/26cve/registry.md` (label + nhánh a/b).
- Metric (D-026): `precision / recall / F1(Applicable)`, `coverage`, `Unknown rate`;
  false-positive / false-negative báo riêng; `recall` giữ **toàn bộ** Applicable ở mẫu số
  (kể cả ca trả Unknown).
- **Unresolved (2 XSS: 5631, 6341)**: loại khỏi mẫu số, báo riêng kèm lý do (D-024).
- Chạy trên **28 resolved** trước; khi 2 XSS có nhãn → thêm 2 hàng + chạy lại (không đổi rule).

## 7. Reproducibility

- Dữ liệu công khai snapshot cố định ngày 2026-10-11 (không fetch live lúc chạy).
- Nhãn chuẩn + HTTP observations đọc từ artifact lab (registry + per-case README/artifacts).
- Code versioned; mỗi lần chạy ghi lại commit + ngày snapshot.

## 8. Còn mở (cần chốt trước khi giao engineer)

1. **Định dạng HTTP observation snapshot** — mỗi case lưu những gì (headers, asset paths, route
   responses) để method "thấy" đúng cái mà lab đã thu, không thừa/thiếu.
2. **Nguồn snapshot cụ thể** — NVD API endpoint / CPE Match / advisory URL nào, lưu ở đâu.
3. **Ngôn ngữ/cấu trúc code** — (engineer đề xuất) script một lần chạy + báo cáo, hay module tái dùng.
4. **Bảng bằng chứng từng CVE** — artifact input chuẩn hóa từ registry (mục §3 ở trên), đây là
   việc làm tiếp theo sau spec này.
