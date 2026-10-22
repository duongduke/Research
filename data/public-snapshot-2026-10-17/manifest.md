# Public-data snapshot manifest — RQ-C1 TOP-UP cohort 2026-10-17

> **Separate cohort.** These 2 CVE IDs were added by D-035 *after* the 2026-10-11
> snapshot was frozen (D-026). Nothing here is backdated into `data/public-snapshot/`,
> and the 30-CVE manifest/hashes are unchanged.

- Cohort / fetch date: **2026-10-17** (D-035 §5 (the 2 top-up CVEs form a separate snapshot cohort with the actual fetch date))
- Manifest generated: `2026-10-17T15:12:16.533Z`
- Generator: `experiments/public-snapshot-2026-10-17/build_cohort.py` (sources: `experiments/public-snapshot-2026-10-17/sources.json`)
- NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0` — no API key; ~5 requests / 30 s. No NVD call was made by this build — all NVD bytes are inherited from the step-1 fetch of 2026-10-17.
- Benchmark CVEs in cohort: 2 (new network fetches this run: 0)

## Summary

- Complete (NVD + CPE + advisory-or-fallback): **2/2**
- With NVD record: 2
- With CPE extraction: 2
- With primary advisory (HTTP 200): 1
- Using a documented fallback advisory: 1
- Partial/failed: 0 (none)

## Per-CVE artifacts

| CVE | nvd.json sha256 | CPE entries | advisory | advisory sha256 | failures |
|---|---|---|---|---|---|
| CVE-2023-23752 | `290310c5f4e5ea8e…` | 1 | advisory.html | `41b8014857705f46…` |  |
| CVE-2023-6553 | `9ba740dd5e485130…` | 1 | [HTTP 403, error body only] + advisory-fallback.json | `b4b39c29adec6d90…` | advisory: primary advisory HTTP 403; advisory (coordinator page, Wordfence Threat Intel): Cloudflare challenge, 0-byte body (nothing to preserve beyond the 0-byte fact) |

## Failure detail

- **CVE-2023-6553** / advisory: primary advisory HTTP 403 (`https://wpscan.com/vulnerability/6a4d0af9-e1cd-4a69-a56c-3c009e207eca`, HTTP 403)
- **CVE-2023-6553** / advisory (coordinator page, Wordfence Threat Intel): Cloudflare challenge, 0-byte body (nothing to preserve beyond the 0-byte fact) (`https://www.wordfence.com/threat-intel/vulnerabilities/id/3511ba64-56a3-43d7-8ab8-c6e40e3b686e`, HTTP 202)

## Notes

- Raw bytes are copied verbatim from the step-1 evidence (`experiments/topup-2026-10-17/sources/`, fetched 2026-10-17); the sha256 is
  computed over the saved file and re-checkable with `experiments/public-snapshot/verify_snapshot.py --dir data/public-snapshot-2026-10-17`.
- `fetched_at_utc` is the **actual fetch time of the bytes** — for every artifact here it is
  inherited from the step-1 fetch (mtime, UTC), and `fetch_mode: inherited_from_step1` says so.
  This build made no network request: re-fetching would create drift inside the same dated cohort.
- `nvd.json` is the unmodified NVD 2.0 API response (structural check: API envelope keys + `cve.id`).
  `cpe.json` is the extraction of the `configurations`/`cpeMatch` nodes, produced by the **same**
  extractor as the 2026-10-11 cohort (imported from `experiments/public-snapshot/fetch_public_snapshot.py`).
- `advisory-fallback.*` is used only when the primary advisory URL is bot-blocked;
  `advisory-primary.error.txt` keeps the failed response body for audit. Both are recorded above.
- Step-1 response headers were not persisted; `content_type` here is derived from the saved bytes
  (`content_type_basis`), not from a recorded header.
- Raw artifacts only: **no labels, no mapping decisions and no interpretation** live in this directory.
