# Danh sách tài liệu tham khảo bổ sung — RQ-C1 (2026-10-20)

> Mục tiêu: nâng danh mục tham khảo lên >10 tài liệu. Các bài dưới đây **đã kiểm chứng là có thật**
> (tên/venue/năm/tác giả khớp kết quả tra cứu). Mỗi mục ghi rõ vì sao liên quan tới đồ án.
> ⚠ = điểm cần đối chiếu thêm trước khi đưa vào bibliography chính thức.

## Hai bài gốc (đã có trong `paper/`)

1. **VAVI** — ASE 2025. ⚠ Nhiều khả năng là *"Vulnerability-Affected Versions Identification: How Far
   Are We?"* (Chen, Liu, Cao, Xiao, Cai, Li, Shi, Sun, Chen, Huo; ASE 2025, pp. 2970–2982, doi:10.1109/ASE63991.2025.00244)
   — đối chiếu lại với file PDF trong `paper/` để chắc tên chính xác. *(Liên quan: nhận diện version bị ảnh hưởng = mức-1 của đồ án.)*
2. **Vuln2Action** — Kumari, Yadav, "Vuln2Action: An LLM-based framework for generating vulnerability
   reproduction steps and mapping exploits", *J. Information Security and Applications* 99:104420, 2026.
   *(Liên quan: hợp nhất CVE/CWE/CPE/CAPEC/Exploit-DB + khoảng trống "không có execution validation" mà đồ án lấp.)*

## Nhóm A — Nhận diện version bị ảnh hưởng (mức-1)

3. **VERCATION** — Cheng, Zhang, Shar, Yang, Dong, Lo, Lv, Shi, Sun, "VERCATION: Precise Vulnerable
   Open-source Software Version Identification based on Static Analysis and LLM", ASE 2025 (Journal-First).
   *(Liên quan: xác định đúng version bị lỗi từ patch + LLM; cùng bài toán E5/affected-range.)*

## Nhóm B — Reachability / applicability (mức-2 — gần nhất với "Applicable" của đồ án)

4. **CPVRA** — Jia, Yang, Feng, Zhao, Li, Ma, "Impact assessment of third-party library vulnerabilities
   through vulnerability reachability analysis", *Computers & Security* 157:104546, 2025.
   *(Liên quan: "reachable" ≈ "applicable"; giảm false alarm bằng điều kiện đường đi.)*
5. **Supply Chain Reaction** — Patel, Snit, Polychronakis, "Supply Chain Reaction: Enhancing the Precision
   of Vulnerability Triage using Code Reachability Information", ACSAC 2025.
   *(Liên quan: reachability function-level giảm ~28–30% báo động sai — đúng tinh thần "affected ≠ applicable".)*
6. **Younis, Malaiya, Ray** — "Using Attack Surface Entry Points and Reachability Analysis to Assess the
   Risk of Software Vulnerability Exploitability", IEEE HASE 2014.
   *(Liên quan: bài kinh điển về đánh giá exploitability bằng attack-surface + reachability.)*
7. **SojiTantei** — Chinthanet, Kula, Zapata, Ishio, Matsumoto, Ihara, "SojiTantei: Function-Call Reachability
   Detection of Vulnerable Code for npm Packages", *IEICE Trans. Inf. Syst.* 2022.
   *(Liên quan: reachability ở mức function call; minh hoạ "client có thể không dính lỗi dù version cũ".)*

## Nhóm C — Ưu tiên hoá lỗ hổng / dự đoán khai thác (độ nghiêm trọng E2)

8. **EPSS** — Jacobs, Romanosky, Edwards, Roytman, Adjerid, "Exploit Prediction Scoring System (EPSS)",
   *Digital Threats: Research and Practice* 2(3), 2021.
   *(Liên quan: dự đoán xác suất bị khai thác; đồ án dùng để lập luận "EPSS không phải bằng chứng applicability".)*
9. (tuỳ chọn) **EPSS v3** — Jacobs, Romanosky, Suciu, Edwards, Sarabi, "Enhancing Vulnerability Prioritization:
   Data-Driven Exploit Predictions with Community-Driven Insights", IEEE EuroS&P Workshops 2023.

## Nhóm D — Web fingerprinting (suy version qua HTTP = E5)

10. **WASABO / Smudged Fingerprints** — Kondracki, Nikiforakis, "Smudged Fingerprints: Characterizing and
    Improving the Performance of Web Application Fingerprinting", USENIX Security 2024.
    *(Liên quan: độ chính xác nhận diện version web qua HTTP — đúng nguồn bằng chứng E5 của đồ án.)*

## Nhóm E — (tuỳ chọn) Báo cáo lỗ hổng dễ hiểu/hành động được

11. **Interpretable Vulnerability Detection Reports** — Mamede, Campos, Le Goues, Abreu, ASE 2025.
    *(Liên quan: ý tưởng "Unknown kèm lý do để người dùng hành động được" — gần với thiết kế abstention của đồ án.)*

## Nguồn chuẩn / cơ sở dữ liệu (đã dùng trong đồ án, tính là tài liệu tham khảo)

- NVD (nvd.nist.gov) — dữ liệu CVE + CPE.
- CVE.org / CVE Records.
- CISA KEV (Known Exploited Vulnerabilities).
- CPE (Common Platform Enumeration) — NIST specification.
- CVSS — Common Vulnerability Scoring System.
- CAPEC — Common Attack Pattern Enumeration and Classification.
- EPSS — FIRST (first.org/epss).

**Tổng:** 2 bài gốc + ~9 bài bổ sung + ~7 nguồn chuẩn ≈ **16–18 mục** (vượt chỉ tiêu >10).
