# Phán quyết mapping top-up (2 CVE) — 2026-10-17

> Researcher (DeepSeek V4 Pro). Phán quyết 10 điểm mở trong
> `notes/collector-mapping-topup-draft-2026-10-17.md`. Đây là phần nghiệp vụ chuẩn bị
> cho **D-037** (freeze mapping 32-CVE). Không đổi nhãn (D-036), không nới tiêu chuẩn
> Applicable, không sửa bản khóa `notes/collector-mapping-30cve.md`.

## Phán quyết (theo số điểm mở của draft)

1. **23752 version probe — giữ 1 request** `/administrator/manifests/files/joomla.xml`.
   `langmetadata.xml` chỉ là quan sát thay thế được ghi chú, **không** đưa vào contract (không tăng budget).
2. **23752 disclosure predicate —** `true_when` = HTTP 200 + JSON:API envelope + `data[]` chứa JConfig keys
   (tối thiểu `dbprefix`,`sitename`,`host`,`user`); **ghi nhận thêm** sự có mặt key bí mật (`password`,`secret`)
   nhưng **không đòi** khớp canary. Canary-value là tiêu chí **nhãn** (D-035 §4), không phải predicate method.
3. **23752 path — rút về `all_of: [p_config_object_readable]`.** Bỏ `p_webservices_config_enabled`
   (`observable:false`, bị bao hàm: route trả JConfig ⇒ plugin đã bật) và `p_api_entry_reachable`
   (bị bao hàm bởi yêu cầu JSON:API envelope) khỏi path. Với info-disclosure, precondition và quan sát
   lành tính trùng nhau — **không** vòng tròn.
4. **23752 no-public control —** giữ làm **validation evidence** (cơ chế), không thành probe runtime
   (401 trên cả 2 build, không phân biệt affected/fixed).
5. **6553 reachability —** probe đúng là **POST benign** (`Content-Dir` = thư mục plugin thật, KHÔNG filter chain).
   Cần capture thêm trên **1.3.7 active + inactive** (hiện chỉ có 1.3.8) trước khi `p_plugin_files_present` verified.
6. **6553 `p_php_filter_wrapper` — BỎ khỏi path.** Filter-chain là gadget khai thác / thuộc tính runtime, không phải
   precondition triển khai. Applicable (mức 2) = bản affected + file lỗi reachable; "gadget có bắn hay không" là mức 3
   (reproduce làm ground truth, method không trả lời — D-008). Path = `all_of: [p_plugin_files_present]`.
7. **6553 one-sided —** xác nhận: `false_when` trống theo G3 ⇒ file vắng/chặn → Unknown, **không có nhánh-b** cho CVE này.
8. **6553 advisory JSON —** thêm nhánh **parse JSON** cho advisory-only baseline (CVE.org CNA `lessThanOrEqual` máy-đọc-được).
   Fixed 1.3.8 lấy từ changelog plugin — ghi provenance.
9. **Freeze —** merge 2 block vào `notes/collector-mapping-30cve.md` → bản 32-CVE → freeze hash mới (D-037).
10. **Snapshot root —** loader chấp nhận root thứ hai `data/public-snapshot-2026-10-17/` (verify cả 2 manifest).

## Kết quả dự kiến (sau freeze + re-run)
fusion TP 3→6, recall 0.107→0.194, F1 0.194→0.324; baseline level-1 TP 10→13, recall 0.357→0.419.
Cả hai cùng tăng (thêm ca dễ-dương); fusion vẫn kém baseline — kết luận định tính không đổi.
