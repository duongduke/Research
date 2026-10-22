# RQ-C1 — Đánh giá CVE cho mục tiêu web (level-2 applicability)

> Đồ án tốt nghiệp. Câu hỏi nghiên cứu: **một CVE có thực sự áp dụng cho một triển khai web cụ thể hay không** — ở mức 2 ("Applicable": bản bị ảnh hưởng được triển khai **và** các điều kiện tiên quyết thỏa mãn), **không phải** mức 3 ("đã khai thác"). Đánh giá **không khai thác trực tiếp**: chỉ quan sát qua HTTP + dữ liệu CVE công khai.

## Tóm tắt

- **Nhãn chuẩn (ground truth):** 32 CVE ID — 30 đã xác định (`Applicable` / `Not Applicable`) + 2 `Unresolved` (XSS, chờ tái hiện thủ công). Tái hiện trong sandbox loopback (WordPress, Drupal, Roundcube, Joomla, Apache/nginx) — 69 case.
- **Phương pháp:** fusion 4 nguồn (CPE / NVD / vendor-advisory / HTTP version) + 4 **baseline** đơn nguồn, trên cùng benchmark và cùng bộ nhãn chuẩn độc lập.
- **Benchmark V3 (2026-10-17, N = 67):** `fusion` precision **1.0**, recall **0.194**, F1 **0.324**; baseline mức-1 (`cpe_only` = `nvd_only` = `http_version_only`) recall **0.419**, F1 **0.553**.

## Kết quả chính (V3)

| method | TP | FP | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|
| `cpe_only` = `nvd_only` = `http_version_only` | 13 | 3 | 11 | 0.813 | 0.419 | 0.553 |
| `advisory_only` | 0 | 0 | 10 | N/A | 0.0 | 0.0 |
| `fusion` | 6 | 0 | 13 | 1.0 | 0.194 | 0.324 |

**Đọc kết quả:** `fusion` **không bao giờ false-positive** (precision 1.0) nhưng recall thấp hơn baseline, vì mức-2 đòi bằng chứng điều kiện tiên quyết mà HTTP thường **không quan sát được** ("trần quan sát"). Trong 25 ca `Applicable` bị `fusion` trả `Unknown`: **3 ca nâng được bằng capture**, **2 ca cần thêm probe**, **20 ca cấu trúc** (version ẩn / điều kiện không có kênh HTTP). Đây là **âm có cấu trúc**: đóng góp là đo được giới hạn đó, không phải tuyên bố "fusion thắng baseline".

## Đóng góp

1. Benchmark nhãn chuẩn từ **tái hiện trong sandbox** (execution evidence), độc lập với phương pháp.
2. Luật fusion **B/P_i** có precedence theo nguồn, **đóng băng trước đánh giá** (chống overfit).
3. Đo được **trần quan sát HTTP** cho level-2 applicability và phân rã `U_A` (fixable / structural).
4. Tách bạch 3 lớp: *affected* ≠ *applicable* ≠ *exploitable*; `Unknown` ≠ "an toàn".

## Cấu trúc repo

- `data/public-snapshot/`, `data/public-snapshot-2026-10-17/` — dữ liệu CVE công khai đóng băng (NVD/CPE/advisory) + manifest + sha256.
- `experiments/methods/` — 5 method + evaluation harness + fixture + kết quả V1/V2/V3 (`output/benchmark*/`).
- `experiments/26cve/`, `experiments/pilot-3cve/`, `experiments/topup-2026-10-17/`, `experiments/reproduce-cve-2021-41773/` — nhãn chuẩn + artifact tái hiện.
- `notes/` — thiết kế fusion, protocol nhãn, mapping 32 CVE (đóng băng), phân tích `U_A`, nháp tổng quan.
- `research/` — đề cương, plan, báo cáo tiến độ (LaTeX/PDF).
- `reviews/` — hồ sơ đánh giá nội bộ.

## Tái lặp

```bash
python3 experiments/methods/build_inputs.py
python3 experiments/methods/fixture/run_fixture.py    # kỳ vọng 193/193 pass
python3 experiments/methods/harness.py load           # kiểm hash mapping + snapshot
python3 experiments/methods/harness.py check          # gate cấu trúc, không tính metric
python3 experiments/methods/harness.py benchmark --run-benchmark --out <thư-mục>
```

> Mapping đóng băng tại sha256 `c186250e…`; snapshot kiểm bằng manifest. Script/compose dùng biến `${...}` — xem `REDACTION.md` để dựng lại lab.

## Giới hạn

- 2 ca XSS (CVE-2023-5631, CVE-2019-6341) chưa resolve — báo cáo riêng, không nằm trong mẫu số metric.
- Một phần nhãn `Applicable` là trạng thái **do lab dựng** (config-on/fixture); recall vì thế là **cận dưới** so với một phân bố triển khai thực tế.
- IP/username/mật khẩu lab đã được redact trước khi công bố — xem `REDACTION.md`.

*Cập nhật: 22/10/2026.*
