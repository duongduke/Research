# experiments/public-snapshot-2026-10-17 — builder for the top-up snapshot cohort

Tooling for `data/public-snapshot-2026-10-17/`, the **separate** snapshot cohort for the 2 CVE IDs
added by **D-035** (CVE-2023-23752, CVE-2023-6553). The frozen 30-CVE cohort
(`data/public-snapshot/`, 2026-10-11, D-026) is **not** touched by anything here.

## Files

| file | role |
|---|---|
| `sources.json` | per CVE: the NVD/advisory/fallback URLs, the **step-1 local files**, their recorded HTTP status, actual fetch time (UTC) and sha256, plus blocked sources and provenance notes |
| `build_cohort.py` | verifies each local source against its recorded sha256, copies it verbatim into the cohort, derives `cpe.json`, writes `manifest.json` + `manifest.md` |

## What it does / does not do

- **No network access.** Every artifact was fetched once on 2026-10-17 in the step-1 verification
  session and is persisted under `experiments/topup-2026-10-17/sources/`. This builder only copies +
  re-hashes. Reason: a second fetch of the same CVE on the same day would either duplicate the
  record or introduce drift inside one dated cohort (NVD is time-varying; the spec freezes bytes +
  hash, no re-fetch).
- **Fails loudly** if a source file is missing, its sha256 differs from the step-1 record, or the NVD
  body is not an NVD 2.0 API envelope for the expected CVE. It never repairs, trims or re-encodes.
- **CPE extraction is shared**: `extract_cpe` is imported from
  `experiments/public-snapshot/fetch_public_snapshot.py`, so both cohorts use byte-identical
  extraction semantics.
- **Byte-stable rebuilds**: `cpe.json` is the only generated file; its `extracted_at_utc` is
  preserved from the first build, so rebuilding does not churn manifest hashes.

## Usage

```bash
python3 build_cohort.py            # write ../../data/public-snapshot-2026-10-17
python3 build_cohort.py --check    # build in a temp dir, diff sha256 against the existing cohort
python3 ../public-snapshot/verify_snapshot.py --dir ../../data/public-snapshot-2026-10-17
```

Expected: `--check` → `sha256 differences: 0`; verifier → `artifacts checked : 7` /
`OK — snapshot matches manifest.json`.

## Adding a CVE (for a future cohort)

Append an entry to `sources.json` with `local_source` + `sha256_expected` + `bytes_expected` +
`http_status` + `fetched_at_utc` + provenance, then rebuild. Do **not** add a CVE to this cohort that
was fetched on a different date — start a new dated cohort instead (D-026/D-035 §5).
