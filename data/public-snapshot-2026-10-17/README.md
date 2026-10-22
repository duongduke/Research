# data/public-snapshot-2026-10-17 — public-data snapshot, TOP-UP cohort (2 CVE IDs)

**Snapshot date: 2026-10-17** — the actual fetch date of the bytes in this directory
(D-035 §5: the 2 top-up CVEs form a *separate* snapshot cohort).

## What this is — and what it is not

- This cohort covers **only** the 2 CVE IDs added after the freeze:
  **CVE-2023-23752** (Joomla! CMS) and **CVE-2023-6553** (WP plugin Backup Migration),
  accepted by **D-035**; ground truth for them is **D-036**.
- It is **separate from** `data/public-snapshot/` (the frozen 30-CVE cohort,
  snapshot date 2026-10-11, D-026). The 30-CVE manifest, hashes and artifacts were
  **not touched** and nothing here is backdated into that manifest.
- Raw artifacts only. **No labels, no mapping/probe decisions, no interpretation**
  live here; those belong in `experiments/26cve/`, `notes/` and `context/`.

## Contents

```
public-snapshot-2026-10-17/
├── manifest.json                 # machine-readable provenance: URL, fetch time (UTC), HTTP, bytes, sha256
├── manifest.md                   # human-readable summary of the same
├── README.md                     # this file
├── CVE-2023-23752/
│   ├── nvd.json                  # verbatim NVD 2.0 API response (vulnStatus: Analyzed)
│   ├── cpe.json                  # derived: configurations/cpeMatch (CPE name + version range + raw tree)
│   └── advisory.html             # vendor advisory (Joomla! Security Centre [20230201])
└── CVE-2023-6553/
    ├── nvd.json                  # verbatim NVD 2.0 API response (vulnStatus: Modified)
    ├── cpe.json                  # derived: configurations/cpeMatch
    ├── advisory-primary.error.txt  # WPScan page, HTTP 403 JS bot-challenge — audit body only, NOT an advisory
    └── advisory-fallback.json    # CVE.org 5.x CNA record (Wordfence, state=PUBLISHED) — authoritative range source
```

## Coverage (actual)

- **2/2** CVEs have an **NVD record + CPE extraction**.
- **1/2** has a **primary advisory page** (CVE-2023-23752, Joomla vendor page, HTTP 200).
- **1/2** uses a **documented fallback** (CVE-2023-6553): both coordinator sources bot-block
  non-browser clients — **WPScan → HTTP 403** (JS challenge) and **Wordfence Threat Intel →
  HTTP 202, 0-byte body** (Cloudflare). The fallback is the **CVE.org CNA record**
  (assigner Wordfence), which is the authoritative affected-version statement for this CVE
  (`<= 1.3.7`). This is the same convention as the frozen cohort's two blocked cases
  (CVE-2020-25213 HTTP 403, CVE-2024-10924 HTTP 202): failed primary body kept for audit,
  explicit fallback, failure recorded in the manifest.
- Fetch window of the bytes: **2026-10-17T13:48:31Z → 13:48:51Z** (see "fetch provenance" below).

## Fetch provenance — no new network fetch in this build

All bytes were already fetched in the step-1 verification session of **2026-10-17** and are
persisted in `experiments/topup-2026-10-17/sources/` (see
`experiments/topup-2026-10-17/manifest.md`). This cohort is a **verbatim, hash-checked copy**
of those bytes plus a **derived** `cpe.json`:

- `build_cohort.py` re-computes the sha256 of every source file and **aborts** on mismatch
  against the step-1 record (all 5 source files matched: 4 artifacts + 1 failed-primary body).
- `fetched_at_utc` in the manifest is the **actual fetch time of those bytes** (UTC, from the
  persisted file mtime — the same convention that reproduces the step-1 download timestamps
  exactly), and each artifact carries `fetch_mode: inherited_from_step1`.
- **Why no re-fetch:** a second live fetch of the same CVE on the same day would either
  duplicate the record or introduce drift inside one dated cohort (NVD is time-varying; spec
  §4.6 says frozen bytes + hash, no re-fetch). Chosen deliberately, recorded here.
- Step-1 response **headers were not persisted**, so `content_type` in the manifest is
  sniffed from the saved bytes (`content_type_basis` says so). HTTP statuses are the step-1
  recorded statuses.

## Verifying

```bash
python3 experiments/public-snapshot/verify_snapshot.py --dir data/public-snapshot-2026-10-17
# expected: artifacts checked : 7 | mismatches 0 | missing 0 | unlisted 0
#           "OK — snapshot matches manifest.json"
```

Rebuild from the step-1 evidence (idempotent; same hashes):

```bash
python3 experiments/public-snapshot-2026-10-17/build_cohort.py          # writes this dir
python3 experiments/public-snapshot-2026-10-17/build_cohort.py --check  # temp rebuild + hash diff
```

## Source-level notes (facts only, no interpretation)

- **CVE-2023-23752** — NVD `configurations` gives `cpe:2.3:a:joomla:joomla\!:*` with
  `versionStartIncluding 4.0.0`, `versionEndExcluding 4.2.8`; the vendor page says
  `Versions: 4.0.0-4.2.7`, `Solution: Upgrade to version 4.2.8`. CWE is recorded by NVD as
  `NVD-CWE-Other` with `CWE-284` supplied by the CISA-ADP source (not by the NVD primary).
  CISA KEV could not be confirmed in step 1 (feed HTTP 403) — unconfirmed, not assumed.
- **CVE-2023-6553** — NVD `configurations` gives
  `cpe:2.3:a:backupbliss:backup_migration:*:*:*:*:*:wordpress:*` with
  `versionEndIncluding 1.3.7`; CVE.org gives `version "0", lessThanOrEqual "1.3.7"`.
  **Neither NVD nor the CVE.org record names the fixed version 1.3.8** — that comes from the
  1.3.8 package (readme changelog + `filterChainFix()` diff in
  `experiments/topup-2026-10-17/fix-diff.md`), not from an advisory sentence. Recorded as-is.
- The Wordfence 202 response was **0 bytes**, so only the fact is recorded (manifest failure
  list); there is no file to persist. The WPScan 403 body is the JS challenge page, contains
  no advisory text, and is stored as `advisory-primary.error.txt` only.
- `nvd.json` was structurally validated during the build (NVD 2.0 envelope keys and
  `vulnerabilities[0].cve.id` == directory CVE). No content was edited or normalised.
- Rebuilds are **byte-stable**: `cpe.json` is the only generated file and its
  `extracted_at_utc` is preserved from the first build (the extraction itself is
  deterministic), so rebuilding does not churn the manifest hashes.
