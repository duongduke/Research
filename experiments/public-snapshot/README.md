# experiments/public-snapshot — snapshot tooling (D-026 / D-027 R4)

Tooling that produces the frozen public-data snapshot at
`data/public-snapshot/` for the 30-CVE RQ-C1 benchmark. **No lab VM is needed** —
this only fetches public data from the workspace host.

## Files

| File | Purpose |
|---|---|
| `sources.json` | Per-CVE advisory URL + provenance (workspace note row, or NVD reference where the note was truncated/missing). Optional documented `fallback_advisory_url` when the recorded URL is bot-blocked. |
| `fetch_public_snapshot.py` | Fetcher: NVD 2.0 record → `nvd.json`; CPE `configurations`/`cpeMatch` extraction → `cpe.json`; advisory → `advisory.<ext>`. Writes `manifest.json` + `manifest.md` (URL, actual fetch timestamp, HTTP status, bytes, sha256). |
| `verify_snapshot.py` | Independent check: re-hashes every artifact against `manifest.json`. |
| `snapshot_report.py` | Mechanical data-quality report (CPE entry counts, missing `configurations`, advisory status). No interpretation. |

## Reproduce

```bash
cd /mnt/d/ADMIN/Documents/do_an_tot_nghiep
python3 experiments/public-snapshot/fetch_public_snapshot.py          # all 30 CVEs -> data/public-snapshot
python3 experiments/public-snapshot/verify_snapshot.py --dir data/public-snapshot
python3 experiments/public-snapshot/snapshot_report.py --dir data/public-snapshot
```

Useful flags: `--only CVE-XXXX-YYYY` (repeatable), `--merge` (update an existing
manifest instead of replacing it), `--skip-existing`, `--no-advisory`,
`--nvd-sleep N`.

## Design / reproducibility notes

- **Rate limits.** No NVD API key ⇒ ~5 requests / 30 s. The fetcher sleeps 7 s
  between NVD requests and backs off on HTTP 403/429/5xx.
- **Verbatim bytes.** Responses are written unchanged; `sha256` is computed over
  the saved file. Nothing is re-encoded, prettified or normalised.
- **Manifest paths are relative** to the snapshot directory, so the snapshot can be
  verified after being moved/copied.
- **Failures are recorded, never fabricated.** A non-200 advisory is listed in the
  manifest failure list; the failed response body is kept only as
  `advisory-<role>.error.txt` for audit, never as `advisory.<ext>`.
- **`fallback_advisory_url` is explicitly labelled.** It is attempted only when the
  recorded URL fails, is saved as `advisory-fallback.<ext>`, and both the primary
  failure and the fallback provenance appear in the manifest.
- **`fetch timestamp`** is the wall-clock UTC time the response was received (not a
  nominal snapshot date).

## Advisory-URL provenance (two edge cases)

- **Truncated in the workspace note** → full URL resolved from the NVD 2.0 record
  references and recorded in `sources.json`: CVE-2024-28000 (Patchstack),
  CVE-2021-44026 (Roundcube commit).
- **No URL recorded for the 3 replacement CVEs** (`registry.md` /`selection-log.md`)
  → CVE-2023-5798 uses the WPScan URL from
  `experiments/26cve/CVE-2023-5798/README.md`; CVE-2021-24917 and CVE-2023-28121 use
  the NVD-reference vendor/advisory URLs.

## Known data-quality caveats (facts, not conclusions)

- CVE-2021-23017's NVD record has 25 CPE match entries (25 vulnerable, 5 with explicit
  version ranges) and shared httpd/roundcube advisory URLs are reused across sibling
  CVEs — relevant to the redundancy problem in D-017.
- The advisory page for CVE-2023-5631 (`roundcube.net` 1.6.4 announcement) describes the
  fix but does not restate affected version ranges; the CPE/NVD record does.
