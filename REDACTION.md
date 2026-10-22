# REDACTION.md — Lab secrets removed before public release

_Biên tập cơ học (mechanical redaction). Không thay đổi nội dung nghiên cứu._
_Editorial pass only — no research content was changed._

---

## Vì sao (Why)

Repo này được công bố **public** trên GitHub. Các artifact lab (compose file, script
setup/repro, log, README ca bệnh) chứa thông tin chỉ nên tồn tại trong lab nội bộ:
mật khẩu mặc định của lab, IP VM, username VM và home-path.

This repository is published **publicly**. Lab artifacts contained credentials,
the lab VM address, the VM username, and home-directory paths. Those are replaced
by placeholders. Nothing else was edited.

## Đã redact (What was replaced)

### 1. Mật khẩu lab (5 chuỗi) → placeholder / biến môi trường

| Ngữ cảnh (context) | Dạng sau redaction (after) |
|---|---|
| `docker-compose.yml` / YAML | `${MARIADB_ROOT_PASSWORD:-changeme}`, `${DB_PASSWORD:-changeme}` (biến môi trường, mặc định `changeme`) |
| `db-init/*.sql` | `IDENTIFIED BY '<set-your-own-db-password>';  -- redacted: set your own password` |
| Shell script (`*.sh`) | `${MARIADB_ROOT_PASSWORD:-changeme}`, `${DB_PASSWORD:-changeme}`, `${WP_ADMIN_PASSWORD:-changeme}`, `${WP_AUTHOR_PASSWORD:-changeme}`, `${WP_EDITOR_PASSWORD:-changeme}` |
| Python script (`*.py`) | `<lab-root-pass>`, `<lab-db-pass>`, `<lab-admin-pass>`, `<lab-author-pass>`, `<lab-editor-pass>` |
| Văn xuôi (README, `*.txt`, log, comment) | cùng các placeholder `<lab-*-pass>` |

Năm mật khẩu (root MariaDB, user DB, admin WordPress/Drupal, author, editor) không
còn xuất hiện dưới dạng chuỗi literal ở bất kỳ file nào sẽ được commit.

**Lưu ý khi chạy lại lab (note when re-running the lab):** các script/ compose giờ
đọc biến môi trường với giá trị mặc định `changeme`. Muốn tái lập đúng môi trường
cũ, hãy export các biến `MARIADB_ROOT_PASSWORD`, `DB_PASSWORD`,
`WP_ADMIN_PASSWORD`, `WP_AUTHOR_PASSWORD`, `WP_EDITOR_PASSWORD` trước khi chạy,
và tự đặt mật khẩu trong `db-init/*.sql` (dòng đã có comment `-- redacted`).

### 2. Định danh hạ tầng lab → placeholder

| Trước (before) | Sau (after) |
|---|---|
| IP VM lab (hai NIC nội bộ) | `<lab-ip>` |
| username VM (hai username dùng để SSH vào VM lab) | `<lab-user>` |
| `user@ip` (ví dụ `ssh <user>@<ip>`) | `<lab-user>@<lab-ip>` |
| `/home/<user>/...` | `~/...` |

### 3. Hai mục bổ sung ngoài bảng token ban đầu (two extra items, same class)

Phát hiện khi quét lại sau khi redact, cùng loại thông tin nên được xử lý như trên:

- mật khẩu admin Joomla dùng trong script cài đặt/README của top-up cohort →
  `<lab-admin-pass>` (2 chỗ: `cases/_stack/README.md`, `cases/_stack/scripts/install-joomla.py`);
- địa chỉ NIC thứ hai của VM lab trong `lab/Ke_hoach_web_lab.md` → `<lab-ip>`.

### 4. Giữ nguyên có chủ ý vì là bằng chứng đo (kept as measured evidence)

- Canary của ca CVE-2023-23752 (`RQ-C1-CANARY-…`, các giá trị `$password`/`$secret`
  cố tình gieo vào cấu hình Joomla): giá trị canary **chính là** dữ liệu quan sát
  của lỗ hổng (API trả về mật khẩu DB). Đây là credential dùng một lần trong lab,
  không tái sử dụng được ở nơi khác; redact sẽ làm sai lệch bằng chứng nên giữ lại.
  Người đọc cần hiểu đây là canary của lab, không phải credential thật.

## Giữ nguyên có chủ ý (Deliberately preserved)

- `127.0.0.1`, `localhost` — địa chỉ loopback, không nhận dạng được máy nào.
- `attacker:8000`, `lab.test`, `labuser`, `wpuser` — hostname/nhãn nội bộ giả lập,
  không phải thông tin đăng nhập.
- Toàn bộ nội dung nghiên cứu: nhãn `Applicable` / `Not Applicable` / `Unresolved`,
  số liệu benchmark, mã HTTP, hash sha256, version/build, digest image, port, ngày
  thu thập, các neo đóng băng (`notes/collector-mapping-30cve.md`,
  `experiments/26cve/registry.md`, `experiments/26cve/selection-log.md`).

## Không bị đụng trong lần redaction này (Untouched)

`notes/`, `experiments/26cve/registry.md`,
`experiments/26cve/selection-log.md`, `data/`, `research/`, `context/`, `paper/`,
`legacy/`, `tmp/`, `.opencode/`, `.gitignore`.

Không có file nào trong các thư mục trên bị sửa. Không nhãn, số liệu, kết quả hay
quyết định phương pháp nào bị thay đổi; đây thuần tuý là thay chuỗi ký tự.

## Phạm vi thay đổi (Scope of the edit)

- 87 file: 86 file dưới `experiments/` + `lab/Ke_hoach_web_lab.md`.
- Chỉ các dòng chứa token bị thay; số dòng, thứ tự dòng, ký tự xuống dòng
  (kể cả CRLF trong artifact HTTP thô) và mọi byte khác được giữ nguyên.
  Đã kiểm tra: mọi dòng thay đổi đều chứa token gốc và placeholder tương ứng;
  không có dòng nào khác bị sửa.
- Không file nào bị xoá, đổi tên hay di chuyển.
