# Review collector/mapping spec — 11/10/2026

Phạm vi: `notes/collector-mapping-spec-2026-10-11.md`, đối chiếu rule/protocol,
context và các artifact HTTP đã có. Review schema, không chạy collector, không
kiểm chứng toàn bộ tín hiệu hoặc audit toàn bộ snapshot. Đề xuất ghi ở
**D-028 PROVISIONAL**; spec và các rule/nhãn đã ghi được giữ nguyên.

## Kết luận

Cách tách (A) tri thức tham chiếu và (B) quy tắc đo đã xử lý đúng định hướng R3.
Ghi các CVE pilot và dấu hiệu dùng phát triển, không gọi toàn bộ benchmark là
held-out sạch, là cách báo cáo phù hợp. Spec dùng được làm cơ sở điền mapping.

Trước khi giao điền đồng loạt, cần làm schema rõ hơn ở các mục dưới đây. Chưa
cần mở lại B/P_i hoặc metric: các vấn đề ở đây thuộc việc biến phép quan sát
thành bằng chứng có phạm vi, provenance và ngân sách xác định.

## R1 — Gắn reference theo nguồn; tách extraction khỏi matching

**Căn cứ:** schema dòng 25–35: một `affected_range`, `maps_to: [E5, P1]`, và
`interpret` gộp asset version với kết luận thuộc dải.

Lưu range/patch/precondition với source ID và artifact/field của snapshot.
Nếu chỉ có một dải tổng hợp, implementation dễ cho CPE-only dùng luôn dải vendor
được chọn cho fusion. Cần biết chính xác E1 nào được mỗi phương pháp phép đọc.
CPE và NVD cùng nội dung vẫn giữ nguồn gốc, không bịa khác biệt giữa hai baseline.

Collector trước hết trả quan sát: component/product, version string hoặc tập
ứng viên, cùng request/response provenance. Matching version với range thuộc
phương pháp, dùng reference được phép cho phương pháp đó. Ví dụ asset `ver=...`
là E5; không tự sinh một E1=True dùng chung cho mọi baseline. Không viết mapping
chỉ nhận diện đúng một phiên bản vulnerable đã dựng, bỏ qua fixed/unknown version.

Ghi rõ evidence visibility: các baseline theo version nhận E5 và nguồn reference
được khai báo; tín hiệu E6 về target không tự lọt vào Advisory-only hay CPE-only.
Có thể dùng chung raw HTTP captures/collector cho các phương pháp rồi lọc đúng
input; không cần cố tạo khác biệt thu thập khi không có cơ sở.

## R2 — Schema phải biểu diễn đường tác động, không chỉ một danh sách điều kiện

**Căn cứ:** `reference.preconditions` hiện là danh sách phẳng.

Cho từng condition/predicate một ID ổn định. Thêm các `paths` với `all_of` các
condition ID và phạm vi phiên bản/access model, kèm căn cứ đủ phạm vi đường.
Chẳng hạn REST và JSON:API là hai đường; không AND hai feature thành một điều
kiện duy nhất rồi coi REST tắt là tất cả đường đã chặn. B về affected build được
tính riêng; điều kiện chưa quan sát được nhận Unknown.

Nên có trường biểu diễn không thể quan sát dưới access model/budget hiện tại,
thay vì tạo một probe giả cho mọi precondition. Việc thiếu version không cản
nhánh config-blocked chỉ khi sản phẩm và phạm vi đường đã xác định đủ, đúng với
canonical rule đã sửa.

## R3 — `interpret` cần điều kiện cụ thể và vết kiểm chứng

Một câu prose có thể đủ cho người đọc nhưng còn cho phép nhiều implementation
khác nhau. Ghi rõ trường response/selector/pattern, cách parse/chuẩn hóa,
`true_when`, `false_when`, xử lý nhập nhằng và fallback Unknown. Với version,
giữ giá trị/tập ứng viên; với feature predicate, trả ba giá trị theo mapping.

Thêm `validation.status`, control state IDs và artifact ref trỏ đúng bằng chứng
HTTP dùng kiểm mapping. Tách **mapping chưa được kiểm chứng** khỏi **runtime
response không đủ căn cứ**; cả hai có thể dẫn tới Unknown nhưng có lý do khác.
Một boolean “đã kiểm” không thay thế được trace đến case/config/access model.

Đối chứng xác nhận **trạng thái predicate**, không phải chỉ nhãn tổng thể CVE.
Ví dụ hai deployment WordPress 5.7.0/PHP 8.0.3 và 5.7.1/PHP 8.0.6 trong README
CVE-2021-29447 đều cho dấu hiệu PHP 8; P_PHP8=True ở cả hai. Bản fixed không
biến feature PHP 8 thành False. Tương tự, bật 2FA và bị affected là hai câu hỏi
khác nhau. HTTP 404/403 đơn lẻ vẫn không tự là negative signal.

## R4 — Khóa contract request, auth và ngân sách tổng

**Căn cứ:** schema có `request`, `access_model`, `budget: 1`; quy tắc chung chỉ
GET/HEAD và tổng <=20 request/case.

Ghi contract toàn case: max requests, timeout, redirect/retry policy, thứ tự/
điều kiện chọn probe, cách tính request dùng chung và fallback khi hết budget.
Tổng tính trên network requests thật, gồm redirect/retry/auth khi có, không chỉ
cộng số probe khai báo. Hai extraction trên cùng response không thành hai request.

Với authenticated observation, ghi tài khoản/role hoặc session được cung cấp
theo access model, cách chuẩn bị session và ngân sách. GET/HEAD không tự login
vào một webapp yêu cầu POST. Nếu session cấp sẵn ngoài collector thì phải nói
rõ; không dùng cookie được tạo từ PoC hoặc quyền nội bộ suy từ ground truth để
làm input. Đây là làm rõ access đã cho phép, không đề xuất mở rộng phương thức.

Riêng dấu hiệu route `two_fa` 400/404: ghi exact URL, HTTP method và response body
predicate/error code, kèm artifact của request quan sát không kích hoạt lỗi.
Không mặc định response của POST reproduction giống GET/HEAD trong collector.
Nếu chưa có bằng chứng GET/HEAD phù hợp, tín hiệu vẫn cần validation; không tự
chuyển sang dùng payload/auth-bypass để có tín hiệu dương.

## R5 — Đơn vị đếm và development use cần ghi theo CVE/case

**Căn cứ:** §3 gọi “toàn bộ 30 ca (28 resolved + 2 Unresolved)”.

Đây là **30 CVE IDs**, không phải 30 case: version/config/access model có thể
tạo nhiều case. Hiện 28 IDs có ca được gán nhãn và 2 IDs manual-pending; vẫn báo
số case resolved/unresolved thực tế riêng. Unresolved không đóng góp precision/
recall/F1 của nhóm đã chấm, nhưng giữ capture/dự đoán nếu có và báo riêng.

Ghi per-CVE/per-case `used_for_rule_development`, `used_for_signal_development`
và lý do/artifact. Danh sách bốn CVE pilot là điểm khởi đầu; các CVE dùng chọn/
tinh chỉnh tín hiệu ngoài pilot cũng cần được ghi. Chỉ thấy một header trong
reproduction không tự đồng nghĩa đã dùng CVE đó chỉnh phương pháp; ghi hành vi
thực tế, không tự coi cả họ WordPress hay Roundcube là development.

Báo kết quả toàn benchmark và theo nhóm có development use; chỉ gọi nhóm khác
là held-out nếu có căn cứ tách biệt. Không cần tạo một quota CVE mới để xử lý
vấn đề báo cáo này.

## Các trường bổ sung đề xuất (minh họa, chưa có tín hiệu được xác nhận)

```yaml
reference:
  ranges_by_source:
    cpe: {artifact: "...", field: "..."}
    nvd: {artifact: "...", field: "..."}
    advisory: {artifact: "...", field: "..."}
  conditions:
    p_feature_a: {description: "...", source_ref: "..."}
    p_feature_b: {description: "...", source_ref: "..."}
  paths:
    - {id: path_a, all_of: [p_feature_a], scope_ref: "..."}
    - {id: path_b, all_of: [p_feature_b], scope_ref: "..."}
method:
  contract:
    access_model: unauth
    max_requests_per_case: 20
    redirect_policy: "..."
    retry_policy: "..."
    timeout_seconds: "..."
  probes:
    - id: observe_feature_a
      request: {method: GET, path: "..."}
      maps_to: p_feature_a
      interpret:
        true_when: "..."
        false_when: "..."
        ambiguity_when: "..."
        otherwise: Unknown
      validation: {status: pending, control_state_ids: [], artifact_refs: []}
development_use:
  used_for_rule_development: false
  used_for_signal_development: false
  reason_ref: "..."
```

Vẫn cần extraction E5 và per-method evidence visibility theo R1; snippet này
chỉ minh họa các trường bổ sung, không phải mapping của một CVE thật hoặc file
methodology đã được duyệt.

## Trạng thái snapshot quan sát được trong lượt review

`data/public-snapshot/manifest.md` đã xuất hiện. Manifest đang báo NVD và CPE
extraction cho 30 IDs, advisory 28/30, thiếu advisory 25213 và 10924. Đây là số
manifest khai báo tại lúc đọc, chưa audit nội dung/hash/chất lượng trích xuất.
Checkpoint engineer CURRENT_STATE §40 ghi snapshot đã được tạo/kiểm hash, kèm
vendor fallback cho hai primary fetch thất bại. Giữ riêng việc hoàn thành artifact
đó với phạm vi review collector; không sửa dữ liệu engineer hoặc tự khẳng định
đã audit nội dung.

## Bước tiếp theo

Bổ sung các trường/cách ghi trên vào schema, điền từng CVE cùng source refs,
probes và control artifacts, rồi khóa collector/mapping thực tế. Schema có thể
hỗ trợ điền ngay; chưa nên coi việc có schema là đã hoàn tất hoặc khóa R3.

## Đối chiếu sau khi áp R1–R5 vào schema (11/10/2026)

Đã đọc lại spec, D-028 effect và TODO. Các trường source references, condition
IDs/paths, response predicates/validation refs, request contract và development
use đã được bổ sung. Cách đếm CVE/case và phân biệt feature-state với nhãn CVE
được giữ đúng. Có thể dùng schema này để giao phần trích xuất/soạn mapping.

**Một câu mới cần sửa để tuân thủ R1:** §4.3 viết “Advisory không machine-readable
→ range lấy từ CPE/NVD; advisory cho precondition + patch”. Câu này trái với
`ranges_by_source` và tập input của Advisory-only: khó trích dữ liệu không cho
phép dùng nguồn khác rồi vẫn gọi là advisory-only. Đề nghị diễn đạt:

> Dải và tiền điều kiện của advisory được trích/chuẩn hóa từ chính nội dung
> advisory đã lưu, kèm artifact/đoạn làm căn cứ. Nếu nguồn đó không đủ thông tin,
> ghi thiếu dữ liệu và trả Unknown cho phần chưa xác định. Fusion được dùng
> CPE/NVD theo quyền nguồn đã khai báo; Advisory-only không tự vay dải của chúng.

Đây là áp dụng yêu cầu source visibility đã ghi ở R1/D-028, không đề xuất đổi
tập phương pháp. Review chưa sửa spec hoặc chấp nhận một comparator hybrid.

**Điền bảng không tự là xác minh mapping:** registry/README/snapshot đủ để trích
reference, mô tả preconditions và soạn probe. `validation.status=verified` cần
artifact của đúng request quan sát HTTP, đúng access model và control states.
Log của PoC, metadata nội bộ hoặc nội dung README kể lại reproduction không
tự là bằng chứng một GET/HEAD an toàn quan sát được điều kiện đó. Nếu bằng chứng
HTTP chưa có, ghi pending/needs_control và lý do Unknown; điều kiện đã xác định
không quan sát được dưới contract thì observable=false. Các điểm này đã có
trong yêu cầu validation, không phải thêm một mục tiêu benchmark mới.

Khi điền file cụ thể, kiểm tra tất cả condition ID trong `paths.all_of` đã được
định nghĩa, artifact/field refs tồn tại và input filter đúng từng phương pháp.
Template hiện dùng các ID minh họa từ nhiều CVE; không sao chép nguyên template
thành một mapping thật có condition ID chưa được khai báo.

Trạng thái: phần schema đã bổ sung; còn chỉnh câu §4.3 và điền/kiểm chứng/khóa
mapping thực tế. D-028 giữ PROVISIONAL. Snapshot đã có artifact theo checkpoint
engineer; lượt này chỉ đọc README/quality report, không audit toàn bộ nội dung.

## Xác nhận hai chỉnh sửa cuối (11/10/2026)

Đã đọc lại §3 (validation) và §4.3 (nguồn advisory). Hai điểm được sửa đúng:
Advisory-only trích dải từ chính advisory, giữ thiếu dữ liệu khi nguồn không đủ;
probe chỉ được xác nhận bằng artifact HTTP đúng request/access/control states,
không thay bằng log PoC hoặc metadata nội bộ. Yêu cầu source visibility và hai
mức trích xuất/validation đã thống nhất với review.

Schema sẵn sàng cho bước điền mapping 30 CVE. Không có yêu cầu sửa schema mới
trong lượt đối chiếu này. Reference/probe/validation refs cụ thể, trạng thái
pending khi thiếu căn cứ và development use được điền rồi rà trước khi khóa
mapping thực tế. D-028 giữ PROVISIONAL; không chạy lab/collector trong lượt này.
