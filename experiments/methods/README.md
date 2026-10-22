# Phương pháp & evaluation harness — 5 methods + benchmark

Tài liệu này giải thích **phần hiện thực** của đồ án: 5 phương pháp đánh giá mức-2 *applicability* và harness chạy benchmark trên bộ nhãn chuẩn 32 CVE. Mục §3–§5 đi vào code (đặc biệt `fusion()`), các mục còn lại là cách dùng và kết quả.

---

## 1. Năm phương pháp

| Phương pháp | Đầu vào | Ý tưởng | Biết mức-2? |
|---|---|---|---|
| **CPE-only** | dải affected từ CPE + version quan sát | `version ∈ dải → Applicable` | không (chỉ mức 1) |
| **NVD-only** | dải affected từ NVD `configurations` + version | như trên, nguồn NVD | không |
| **Advisory-only** | dải + điều kiện từ vendor advisory | thêm kiểm bản vá, nhưng **không thấy config thật** | một phần |
| **HTTP version-string-only** | chỉ version suy ra từ HTTP + bảng tra dải | baseline "chỉ nhìn banner" | không |
| **Fusion** | hợp nhất cả 4 nguồn + dấu hiệu feature/config qua HTTP | kết luận theo **B/P_i**, trả `Unknown` khi thiếu bằng chứng | có (khi bằng chứng đủ) |

Điểm chung: **thiếu dữ liệu ≠ version ngoài dải**. Mọi phương pháp trả `{Applicable, NotApplicable, Unknown}`; `Unknown` là *từ chối kết luận trung thực*, không phải "an toàn".

---

## 2. Ý tưởng fusion trong một đoạn

Một CVE chỉ **áp dụng** nếu hai điều cùng đúng:

- **`B`** — build đang chạy **thực sự chứa mã bị lỗi** (version ∈ dải affected, hoặc nối được với bản vá);
- **`P`** — tồn tại **một đường tác động** mà **mọi điều kiện bắt buộc** của nó đều thỏa (`P_i = True`).

Nếu `B` sai (build đã vá) → **Not Applicable**. Nếu mọi đường đều bị chặn bởi ≥1 điều kiện thiếu → **Not Applicable** (config-blocked). Còn lại, khi bằng chứng chưa đủ → **Unknown**. Nguyên tắc: **"đủ bằng chứng" = xác định được đủ điều kiện bắt buộc**, *không phải* đếm số nguồn đồng thuận.

---

## 3. Luồng dữ liệu (đọc code theo thứ tự)

```
notes/collector-mapping-30cve.md   ─┐
data/public-snapshot*/             ─┼─► build_inputs.py ─► data/{cases,observations,advisory_ranges}.json
experiments/**/captures, artifacts ─┘                              │
                                                                   ▼
                                                     methods.py  (Context + 5 methods)
                                                                   │
                                              harness.py  ──► output/benchmark*/{predictions,metrics,run-metadata}.json
                                                                   │
                                                     metrics.py (chấm điểm, ghép nhãn)
```

- **`build_inputs.py`** — ETL: đọc mapping + snapshot + capture, kiểm hash artifact, sinh 3 file JSON đầu vào (`cases.json`, `observations.json`, `advisory_ranges.json`). Đây là file lớn nhất (~1.500 dòng) vì mỗi CVE có quy tắc trích xuất riêng.
- **`methods.py`** — 5 phương pháp, là **hàm thuần**: nhận `case` + `Context`, trả dự đoán + lý do + bằng chứng.
- **`harness.py`** — nạp dữ liệu (kiểm sha256 mapping + manifest snapshot), chạy method, ghép nhãn **sau khi** dự đoán, chấm điểm.
- **`metrics.py`** — công thức precision/recall/F1/coverage/Unknown.
- **`fixture/`** — bộ kiểm thử tổng hợp (193 check) chạy cùng code path với dữ liệu thật.

---

## 4. Giải thích `fusion()` từng bước

Hàm ở `methods.py:443`. Các bước dưới đây bám đúng code (số dòng ghi kèm).

### Bước 0 — Lấy bằng chứng đã được "chấp nhận" (dòng 446–461)

```python
preds = ctx.accepted_predicates(case)   # condition_id -> True/False/Unknown
e5    = ctx.e5(case)                    # product + version suy ra từ HTTP
adv   = ctx.advisory_entry(cve_id)      # dải affected (advisory)
cpe   = ctx.cpe_ranges(cve_id, ...)     # dải affected (CPE, đã lọc theo product)
nvd   = ctx.nvd_ranges(cve_id, ...)     # dải affected (NVD configurations)
```

Điểm then chốt: `accepted_predicates` áp **cổng G7** (`methods.py:190–222`) — một probe chỉ cho ra `True`/`False` khi `validation.status == "verified"`. Probe `pending`/`needs_control` → **`Unknown`**, dù capture nói gì. Điều kiện không có probe (`observable:false`) → `Unknown`. Đây là lý do fusion abstain nhiều (xem §5).

`e5()` (`methods.py:224–274`) chỉ dùng observation **verified** của các condition nhận diện sản phẩm, đối chiếu `identity_tokens`/`identity_family`; không thấy version → `version_status = "not_observed"`.

### Bước 1 — Tier 3 (E4): build đã vá chưa? (dòng 469–478)

```python
link = ctx.patch_linkage(case)
if link["linked"]:
    B = False          # nhánh a — kết luận được kể cả khi version ẩn
```

`patch_linkage` (`methods.py:276–294`) chỉ trả `linked=True` khi có **condition `kind: build`** liên quan bản vá với **probe verified = True**. Một bản vá của distro mà **không nối được** với target đang chạy **không** tính.

> Vì sao tier 3 chạy **trước** tier 1/2: một build đã vá là bằng chứng âm đủ mạnh, không cần biết version.

### Bước 2 — Tier 1/2: tính `B` từ identity + version (dòng 479–520)

```python
if not product_identified:     B = Unknown   # chưa nhận diện được sản phẩm
elif version is None:          B = Unknown   # không quan sát được version ≠ ngoài dải
else:
    adv_v, nvd_v, cpe_v = verdict từng nguồn (True / False / None)
    # precedence advisory > NVD > CPE cho CÙNG khẳng định + CÙNG phạm vi:
    if adv_v is not None:                     B = adv_v
    elif nvd_v is not None and cpe_v is not None and nvd_v != cpe_v:
                                              B = Unknown   # mâu thuẫn cùng tầng
    elif nvd_v is not None:                   B = nvd_v
    elif cpe_v is not None:                   B = cpe_v
    else:                                     B = Unknown
```

Hai chi tiết dễ sai:
- Dải rỗng **sau khi lọc product** = *thiếu dữ liệu*, trả `None` (Unknown), **không** phải `False` (dòng 489–497).
- Mâu thuẫn giữa NVD và CPE (cùng tầng) mà không có advisory phân xử → `Unknown`, và **mâu thuẫn được ghi lại** trong `evidence` (dòng 518–520), không giấu.

`versioncmp.match_ranges` quyết định `True/False/None`; xem §5.

### Bước 3 — Tier 4: tính `P_i` cho từng đường tác động (dòng 525–543)

```python
for path in ctx.paths(cve_id):                 # mỗi path có all_of = danh sách condition_id
    vals = [ _pred(preds, c) for c in path["all_of"] ]
    if any(v == "False" for v in vals):        P_i = "False"   # thiếu ≥1 điều kiện → đường bị chặn
    elif vals and all(v == "True" for v in vals): P_i = "True" # mọi điều kiện đều thỏa → đường mở
    elif not vals:                              P_i = "True"    # conjunction rỗng (không có tiền điều kiện)
    else:                                       P_i = "Unknown"
```

- "Đường bị chặn" chỉ cần **một** điều kiện `False` — không cần mọi điều kiện vắng.
- `P_i = True` đòi **tất cả** điều kiện `True`; chỉ một cái `Unknown` là cả đường `Unknown`.
- Conjunction rỗng = đường không có tiền điều kiện quan sát được (ví dụ CVE-2021-23017) → `True`, nhưng vẫn cần `B`.

### Bước 4 — Kết luận canonical (dòng 545–565)

```python
if B is True and any(P_i == "True"):                       → Applicable
elif B is False:                                            → NotApplicable   (nhánh a)
elif product_identified and scope_ok and all(P_i == "False"): → NotApplicable (nhánh b)
else:                                                       → Unknown
```

- **Nhánh b không cần `B=True`**: nếu mọi đường đều bị chặn thì kết luận âm bền vững dù build affected hay không; thiếu version chỉ làm `B` chưa rõ, không phá nhánh này.
- `Unknown` luôn kèm danh sách `undecided_conditions` (điều kiện chưa giải được) để truy vết.

### Trace thật (từ `output/benchmark-v3/predictions.json`)

| Case | B | P_i | Kết quả | Lý do |
|---|---|---|---|---|
| `CVE-2017-1001000__vuln` | True (4.7.1 ∈ dải) | `p_rest_reachable = True` (200 + body `routes`) | **Applicable** | đường mở |
| `CVE-2024-10924__2fa_on` | True (9.1.1.1 ∈ dải) | `p_2fa_enabled = True`, `p_skip_onboarding_route = True` | **Applicable** | đường mở |
| `CVE-2024-10924__2fa_off` | (không cần) | `p_2fa_enabled = False` (404 `rest_no_route`) | **Not Applicable (b)** | mọi đường bị chặn |
| `CVE-2021-41773__weakened` | True (2.4.49 ∈ dải) | `p_diroots_require_all_granted = Unknown` (`observable:false`) | **Unknown** | trần quan sát |
| `CVE-2021-23017__backport` | Unknown (version ẩn) | path rỗng → `True` | **Unknown** | thiếu `B` |

---

## 5. Các hàm phụ trợ quan trọng

- **`Context`** (`methods.py:73–294`) — lớp truy cập dữ liệu đóng băng: `conditions`, `paths`, `probes` từ mapping; `cpe_ranges`/`nvd_ranges` lọc theo `vendor:product` của case (chỉ giữ entry `vulnerable`, bỏ entry sai product).
- **`accepted_predicates`** (`190–222`) — **cổng G7**: chỉ probe `verified` mới cho `True/False`; `pending`/`needs_control`/không probe → `Unknown`.
- **`e5`** (`224–274`) — version/identity từ HTTP; khớp token sản phẩm; không thấy → `not_observed`.
- **`patch_linkage`** (`276–294`) — E4: chỉ nhận bằng chứng build đã vá **nối được với target**.
- **`versioncmp.py`** — so version: `release` (số chấm, `5.0 == 5.0.0`, pre-release xếp dưới), `lex`; **distro revision vs upstream version không so được → `None`** (`scope_mismatch`), nên method abstain thay vì đoán. `match_ranges` trả `True/False/None`.
- **`metrics.py`** — `precision = TP/(TP+FP)`; `recall = TP/(TP+FN_def+U_A)` (giữ `U_A` trong mẫu số); `F1 = 2TP/(2TP+FP+FN_def+U_A)`; `coverage`, `Unknown rate`; mẫu số 0 → `N/A`.
- **`harness.py`** — `load` (kiểm sha256 mapping + manifest snapshot), `check` (gate cấu trúc, **không** tính metric), `benchmark --run-benchmark` (chạy 5 method, ghép nhãn **sau** dự đoán, chấm điểm). **Label isolation**: method chỉ nhận case view không có nhãn/build/config; lỗi nếu nhãn rò vào.

---

## 6. Bộ dữ liệu (đóng băng trước đánh giá)

- **32 CVE ID**, **69 case** = 30 resolved (`Applicable`/`NotApplicable`) + 2 `Unresolved` (XSS, chờ tái hiện thủ công).
- Nhãn chuẩn lấy từ **tái hiện trong sandbox** (execution evidence), **độc lập** với phương pháp — xem `experiments/26cve/registry.md`.
- Input đóng băng: mapping `notes/collector-mapping-30cve.md` (sha256 `c186250e…`), snapshot `data/public-snapshot*/` (kiểm bằng manifest sha256).

## 7. Cách chạy lại

```bash
python3 experiments/methods/build_inputs.py                 # Phase A — sinh input
python3 experiments/methods/fixture/run_fixture.py          # Phase C — 193 kiểm thử, kỳ vọng pass hết
python3 experiments/methods/harness.py load                 # kiểm hash mapping + snapshot
python3 experiments/methods/harness.py check                # gate cấu trúc, không tính metric
python3 experiments/methods/harness.py benchmark --run-benchmark --out <thư-mục>
```

## 8. Kết quả V3 (2026-10-17, N = 67)

| Phương pháp | TP | FP | TN | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| `cpe_only` = `nvd_only` = `http_version_only` | 13 | 3 | 11 | 0.813 | 0.419 | 0.553 |
| `advisory_only` | 0 | 0 | 10 | N/A | 0.0 | 0.0 |
| **`fusion`** | **6** | **0** | **13** | **1.0** | **0.194** | **0.324** |

**Đọc kết quả:** `fusion` **không bao giờ false-positive** nhưng recall thấp hơn baseline, vì mức-2 đòi bằng chứng điều kiện tiên quyết mà HTTP thường **không quan sát được** ("trần quan sát"). Trong 25 ca `Applicable` bị trả `Unknown`: 3 ca nâng được bằng capture, 2 ca cần thêm probe, 20 ca cấu trúc. Kết quả thô ở `output/benchmark/` (V1), `output/benchmark-v2/`, `output/benchmark-v3/`.

## 9. Cấu trúc thư mục

- `methods.py` — `Context` + 5 phương pháp; `fusion()` (443) là thuật toán chính.
- `versioncmp.py` — so version/range (release, pre-release, distro revision).
- `metrics.py` — công thức metric.
- `harness.py` — load + kiểm hash, chạy, chấm điểm.
- `build_inputs.py` — ETL: mapping + snapshot + capture → `data/{cases,observations,advisory_ranges}.json`.
- `fixture/` — bộ kiểm thử tổng hợp + kết quả.
- `output/` — kết quả benchmark V1/V2/V3.

## 10. Chi tiết kỹ thuật

Nhật ký hiện thực, các bất biến (invariants), lịch sử sửa và quyết định kỹ thuật nằm ở **`IMPLEMENTATION-NOTES.md`**. Các ghi chú theo từng vòng (`NOTE-*.md`, `REPORT-step3.md`) giữ nguyên lịch sử làm việc.
