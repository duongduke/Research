# Method implementation spec — bước 3 (code 5 method + harness)

> Ngày: 15/10/2026. Researcher (DeepSeek V4 Pro). Trạng thái: **thiết kế triển khai** —
> vận hành hoá D-026 (rule khóa) + D-030 (mapping khóa). KHÔNG phải quyết định phương pháp
> mới (D-011 vẫn PROVISIONAL). Căn cứ: `notes/fusion-design-2026-10-10.md` §3–§4 (D-026),
> `notes/ground-truth-protocol.md` (metric), `notes/collector-mapping-30cve.md` (D-030),
> `notes/collector-mapping-spec-2026-10-11.md` (D-028), `reviews/Xac_nhan_ban_khoa_mapping_D030_2026-10-14.md`.

## 1. Nguyên tắc chung (lấy từ xác nhận bước 3)

1. Nạp mapping + snapshot → **kiểm hash/version**; ghi vào run metadata (biết chính xác dữ liệu/rule đã dùng).
2. Collector giữ **observed** product/component/version + provenance; mỗi method chọn đúng source/evidence được phép.
3. **Cổng G7**: `pending`/`needs_control` KHÔNG tạo True/False hoặc E5 từ capture chưa được chấp nhận → runtime Unknown.
4. **B và P_i riêng**: blocked path không đòi `B=True` khi target đúng/phạm vi đủ; missing data/conflict không tự sinh nhãn âm.
5. Loader/eval tách **GT/config nội bộ** khỏi input method; gắn label SAU prediction; không đưa label hay package metadata vào B/P_i.
6. **Case** = product/build/config/CVE/access scope; 28 = CVE IDs đã resolved, KHÔNG phải số case; báo `n_unique_cves`/`n_cases`/labels riêng.
7. Metric theo công thức đã chốt (recall/F1 giữ U_A, tách FN_def khỏi abstention, mẫu số coverage/Unknown rate chung, mẫu số 0 = N/A).

## 2. Mô hình input đánh giá (tái lập được, không chạy lab)

Ba input method **đông lạnh** + hai input do engineer tạo từ artifact:

- **F1** `data/public-snapshot/` — CPE/NVD/advisory (D-026, bytes+hash đã đóng băng).
- **F2** `notes/collector-mapping-30cve.md` — rule method (D-030, hash `f266673ee…`).
- **F3** `notes/fusion-design-2026-10-10.md` §3–§4 — luật 5 method + fusion.
- **M1 (engineer tạo): `observations.json`** — giá trị E5/E6 **quan sát được** theo case/control_state, trích từ artifact HTTP
  đông lạnh (chỉ các capture `verified`). Đây là **input method** (bằng chứng quan sát), KHÔNG phải ground truth.
  Mỗi probe `verified` → ghi observed value (vd `Server: Apache/2.4.49`, `generator: WordPress 5.0`, `X-Powered-By: PHP/8.0.3`,
  `route 200`, `readme Stable tag: …`). Probe `pending`/`needs_control` → ghi `observed: null` + `status` (→ G7 Unknown).
  **KHÔNG** trích từ log PoC/DB/attacker-listener/`dpkg -l`/image digest (đó là GT, không phải quan sát).
- **M2 (engineer tạo): `cases.json`** — danh sách case (product/build/config/CVE/access) + **ground-truth label** (từ registry
  `experiments/26cve/registry.md` + pilot README + D-020…D-024). Label chỉ dùng **sau prediction** để chấm metric (cách ly label).

## 3. Chuẩn hoá range (advisory) — một phần input, không re-fetch

- `cpe.json` / `nvd.json` đã machine-readable (dùng trực tiếp).
- `advisory.html` free-text → engineer chuẩn hoá thành `advisory_range` (op,version) **từ chính advisory đã đóng băng**.
  Advisory không có range máy đọc được (CVE-2019-8942, 2019-10692, 2021-44026, 2020-25213, 2024-10924) → `advisory_range: null`
  → Advisory-only trả Unknown ở mức 1 (spec §4.3). KHÔNG vay CPE/NVD gọi là advisory-only.

## 4. Luật 5 method (tóm tắt; chi tiết = fusion-design §3)

- **CPE-only**: E1(cpe.json range) + E5. Không biết version → Unknown; version ∈ range → Applicable; ∉ → Not Applicable.
  Phải **nhận diện product từ E5** rồi lọc CPE theo product (spec §4.1).
- **NVD-only**: E1 (CPE của NVD = configurations trong nvd.json) + E2 (CVSS/CWE, chỉ metadata) + E5. Luật như CPE-only.
  **Không** thay bằng CNA `affected[]` (D-028 R1). Trùng CPE-only là điều phải BÁO, không bịa khác biệt.
- **Advisory-only**: E1(advisory_range) + E3 (tiền điều kiện) + E4 (patch) + E5. Thứ tự (§3.3): (1) nối được target↔build đã
  vá (E4) → NA-a; (2) không biết version/không range/product chưa khớp → Unknown; (3) version ∉ range → NA; (4) version ∈ range
  ∧ có precondition mà không kiểm được trên máy thật → Unknown (advisory-only thiếu E6); (5) version ∈ range ∧ không có
  precondition trong phạm vi → Applicable.
- **HTTP-version-only**: E5 + bảng range tham chiếu (CPE làm lookup). Chỉ mức 1: version quan sát được → ∈/∉ range; không quan sát
  được → Unknown. Trùng CPE-only/NVD-only khi quan sát được → BÁO.
- **Fusion**: đủ E1–E6, theo B/P_i (mục 6).

## 5. So sánh version (phải đúng boundary; fixture kiểm)

- CPE: `cpeName` exact version (`:2.4.49`, `:4.7`) → `==`; hoặc range qua
  `versionStartIncluding/Excluding` + `versionEndIncluding/Excluding` (đúng inclusive/exclusive).
- Exact-version CVE (1001000, 41773, 42013, 2745) → xử lý `==`; CPE liệt 4.7.2 vulnerable (mâu thuẫn advisory) → **giữ nguyên**
  (CPE-only có thể dương trên GT âm = FP được đo, không hardcode).
- NVD CNA `affected[]` chỉ để provenance, không dùng bởi NVD-only.
- Advisory range → parse `(op, version)`; version comparison theo semantic khi có `versionType: semver`, else lexicographic.

## 6. Fusion B/P_i (fusion-design §4.5, đã bổ sung R1/R2 D-027)

- **B** ∈ {True,False,Unknown}: target chứa build affected (E5 nhận diện + E1 range theo precedence + E4 patch). Precedence cho
  cùng assertion+cùng scope: advisory > NVD > CPE; bằng chứng trực tiếp E6 > suy luận gián tiếp. Mâu thuẫn chưa giải → Unknown.
- **P_i** ∈ {True,False,Unknown}: all-of các precondition (`kind: precondition`) của đường i. `False` khi ≥1 precondition False.
- Kết luận: **Applicable** = B=True ∧ ∃ path P_i=True; **NA-a** = B=False; **NA-b** = target nhận diện đúng ∧ phạm vi đủ ∧ MỌI
  path liên quan P_i=False (KHÔNG cần B=True); **Unknown** = còn lại. Precondition `kind: build` KHÔNG nằm trong P_i (D-030 G1).

## 7. Metric (protocol §"Hai loại Unknown", theo case)

- Đơn vị = **case** (không phải CVE). Confusion: TP/FP/TN/FN_def/U_A/U_N.
- `precision = TP/(TP+FP)`; `recall = TP/(TP+FN_def+U_A)`; `F1 = 2·TP/(2·TP+FP+FN_def+U_A)`; `coverage = (TP+FP+TN+FN_def)/N`;
  `Unknown rate = (U_A+U_N)/N`. Mẫu số 0 → `N/A`; `F1=0` khi TP=0 và mẫu số dương. KHÔNG bỏ U_A/U_N trước khi tính.
- Unresolved (5631, 6341) ngoài mẫu số, báo riêng. Báo `n_unique_cves` / `n_cases` / `n_labels` riêng.

## 8. Fixture tổng hợp (chạy TRƯỚC benchmark — điều kiện chuyển bước 4)

Tạo dataset tổng hợp nhỏ (fake CVE/case/observation) kiểm: (a) boundary inclusive/exclusive/exact; (b) filter product/source;
(c) B/P_i + cổng Unknown (pending/needs_control → Unknown; blocked path không cần B=True; missing data/conflict → Unknown không âm);
(d) cách ly label (method không đọc GT); (e) metric với U_A và mẫu số 0; (f) hash mismatch (mapping/snapshot sai hash → fail).
Chỉ khi fixture pass mới chạy benchmark thật (bước 4). KHÔNG chỉnh cutoff/mapping sau khi xem kết quả benchmark.

## 9. Output + run metadata

- `predictions.json` (theo case, kèm lý do + B/P_i + provenance); `metrics.json` (tổng + theo nhóm development_use).
- `run-metadata.json`: hash mapping + hash snapshot manifest + version + thời điểm; raw captures/predictions tách khỏi bảng metric.
- Nhiều Unknown là **kết quả cần đo** của bản này, không phải lý do nâng validation hay vá theo đáp án.
