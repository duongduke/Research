# research/

Tài liệu LaTeX của đồ án (đề cương, plan, báo cáo tiến độ...). **Mỗi báo cáo = 1 thư mục riêng** (không để `.tex`/`.pdf` rải ở gốc `research/`):

- `de-cuong-do-an/` — đề cương ĐATN (`.tex` → `.pdf`, `build.sh`)
- `plan-so-bo/` — plan sơ bộ (`.tex` → `.pdf`, `build.sh`)
- `bao-cao-tien-do-2026-10-19/` — báo cáo tiến độ 19/10/2026 (`.tex` → `.pdf`, `build.sh`)

Mỗi thư mục có `build.sh` (chạy `lualatex` 2 pass). Quy ước: khi viết báo cáo mới, tạo thư mục
`research/<ten-bao-cao>/` và đặt `.tex` + `build.sh` vào đó.
