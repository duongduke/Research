# data/public-snapshot — frozen public-data snapshot (RQ-C1 benchmark)

**Snapshot date: 2026-10-11** (accepted decision **D-026**: CPE/NVD/advisory data is
snapshotted as of this date; no live re-fetch during evaluation).

This directory is a **frozen artifact**. Do not edit the files in place; regenerate
with the tooling in `experiments/public-snapshot/` (see its `README.md`).

## Contents

```
public-snapshot/
├── manifest.json          # machine-readable provenance: URLs, fetch timestamps, sha256
├── manifest.md            # human-readable summary of the same
├── quality-report.md      # mechanical data-quality report (no interpretation)
├── <CVE-ID>/
│   ├── nvd.json           # verbatim NVD 2.0 API response for the CVE
│   ├── cpe.json           # extracted configurations/cpeMatch (CPE names + version ranges)
│   └── advisory.html      # verbatim vendor/NVD advisory page
│       (advisory-fallback.html + advisory-primary.error.txt where the recorded URL failed)
└── ...
```

## Coverage (actual, 2026-10-11)

- 30/30 benchmark CVEs have **NVD record + CPE extraction**.
- 28/30 have the **advisory URL recorded in the workspace**; 2 use a documented
  fallback because the recorded URL is bot-protected:
  - **CVE-2020-25213** — `plugins.trac.wordpress.org/changeset/2373068` → HTTP 403
    JS bot-challenge to non-browser clients. Fallback: the vendor-hosted
    `wordpress.org/plugins/wp-file-manager/` page/changelog.
  - **CVE-2024-10924** — `wordfence.com/blog/2024/11/...` → HTTP 202 Cloudflare
    challenge, empty body. Fallback: the vendor-hosted
    `wordpress.org/plugins/really-simple-ssl/` page/changelog.
- No NVD record is missing `configurations`; no CVE has zero CPE match criteria.
- Fetch window (actual UTC): 2026-10-11T09:52:39Z → 10:01:16Z.

## Verifying

```bash
python3 experiments/public-snapshot/verify_snapshot.py --dir data/public-snapshot
```

Re-hashes every artifact listed in `manifest.json` (including the failed-response
audit bodies) and reports mismatches, missing files and unlisted files. Expected
output: `OK — snapshot matches manifest.json` (92 hashed artifacts on 2026-10-11).

## Provenance notes

- `nvd.json` / `advisory.*` are raw response bytes; the `sha256` in the manifest is
  over the saved bytes.
- `cpe.json` is a derived extraction of the `configurations` tree in the same
  `nvd.json` (plus the raw tree, kept for audit).
- The advisory URL per CVE and its provenance (workspace note row, or NVD reference
  where the workspace note was truncated/missing) are recorded in
  `experiments/public-snapshot/sources.json` and repeated per CVE in the manifest.
- Raw artifacts live here; **interpretation belongs in `notes/` or `reviews/`, not here.**
