# Public-data snapshot manifest — RQ-C1 30-CVE benchmark

- Snapshot date: **2026-10-11** (D-026 (freeze public CVE data snapshot at 2026-10-11))
- Manifest generated: `2026-10-11T10:01:45.970Z`
- Generator: `experiments/public-snapshot/fetch_public_snapshot.py` (sources: `/mnt/d/ADMIN/Documents/do_an_tot_nghiep/experiments/public-snapshot/sources.json`)
- NVD API: `https://services.nvd.nist.gov/rest/json/cves/2.0` — no API key; ~5 requests / 30 s (sleep=7.0s between NVD calls)
- Benchmark CVEs: 30 (fetched in last run: 3)

## Summary

- Complete (NVD + CPE + advisory): **30/30**
- With NVD record: 30
- With CPE extraction: 30
- With primary (notes-recorded) advisory: 28
- Using a documented fallback advisory: 2
- Partial/failed: 0 (none)

## Per-CVE artifacts

| CVE | nvd.json sha256 | CPE entries | advisory | advisory sha256 | failures |
|---|---|---|---|---|---|
| CVE-2014-3704 | `5a0ed7e6acf8a0d8…` | 2 | advisory.html | `039fef342cd0ef94…` |  |
| CVE-2015-3440 | `b0f4ea66c7ae005b…` | 3 | advisory.html | `9f4428be2a7e109e…` |  |
| CVE-2017-1001000 | `2f02c0af7471c952…` | 3 | advisory.html | `f6eeb96e391e999a…` |  |
| CVE-2018-7600 | `80e03cdc6da47bd7…` | 7 | advisory.html | `b2652b7ad11f576f…` |  |
| CVE-2018-7602 | `2749c24a65bdedf6…` | 6 | advisory.html | `0e972279e9accf48…` |  |
| CVE-2019-10692 | `14f1888752fea8a5…` | 1 | advisory.html | `d69292627fbb2428…` |  |
| CVE-2019-6340 | `9acb64dd70791ed5…` | 2 | advisory.html | `303017746fac3bb4…` |  |
| CVE-2019-6341 | `2fe49b4ef482ac8d…` | 6 | advisory.html | `668998e6571e7b7b…` |  |
| CVE-2019-8942 | `7f1704cf7e9427bc…` | 11 | advisory.html | `304f7469313074dc…` |  |
| CVE-2020-12625 | `87501d72036153b6…` | 7 | advisory.html | `211dd65434f5b824…` |  |
| CVE-2020-12640 | `63facc40131907e7…` | 7 | advisory.html | `211dd65434f5b824…` |  |
| CVE-2020-12641 | `78906b5c04ad1cd8…` | 7 | advisory.html | `211dd65434f5b824…` |  |
| CVE-2020-13671 | `0651432ab614d04f…` | 6 | advisory.html | `5ae156e6de1d9015…` |  |
| CVE-2020-25213 | `b62d3ce68977c4f6…` | 1 | [HTTP 403, no body] + advisory-fallback.html | `5a9a35f531c969a8…` | advisory: primary advisory HTTP 403 |
| CVE-2021-23017 | `2d67e00c97d41284…` | 25 | advisory.html | `c4775a1af300b3a1…` |  |
| CVE-2021-24917 | `69cf203772a0bc09…` | 1 | advisory.html | `2a960479fb565084…` |  |
| CVE-2021-29447 | `1d0f3109292c4f99…` | 3 | advisory.html | `578d1ffd5d2112e2…` |  |
| CVE-2021-41773 | `cee6258f250d2969…` | 7 | advisory.html | `3edeb2dde2f2207c…` |  |
| CVE-2021-42013 | `d581959590c39c56…` | 10 | advisory.html | `3edeb2dde2f2207c…` |  |
| CVE-2021-44026 | `3114b6d3ca2ebb3c…` | 7 | advisory.html | `b37e8641b28b2827…` |  |
| CVE-2022-21661 | `8dd8e2f02947f80a…` | 27 | advisory.html | `af8d6b10fec0256a…` |  |
| CVE-2023-2745 | `96b4f5436944391e…` | 22 | advisory.html | `c4fc1a3057e5f025…` |  |
| CVE-2023-28121 | `acbcb0ffddc67e28…` | 9 | advisory.html | `58437f304bdd5daa…` |  |
| CVE-2023-32243 | `4fbf41807ae60591…` | 1 | advisory.html | `39becd1d42467140…` |  |
| CVE-2023-3460 | `536169e97d2d2949…` | 1 | advisory.html | `8bfb14d74ece4b1e…` |  |
| CVE-2023-5631 | `c9c60478c762a13a…` | 7 | advisory.html | `b592d9ccb42bf7dc…` |  |
| CVE-2023-5798 | `23c1e4e1961ae006…` | 1 | advisory.html | `f29264eb9609681a…` |  |
| CVE-2024-10924 | `2ae68b3dffb6ef5f…` | 3 | [HTTP 202, no body] + advisory-fallback.html | `fc902c1048926731…` | advisory: primary advisory HTTP 202 |
| CVE-2024-28000 | `d482f9413a13a23e…` | 1 | advisory.html | `b477bf708115b380…` |  |
| CVE-2024-37383 | `e03427db611a48a8…` | 3 | advisory.html | `600f366fdbd5ab03…` |  |

## Failure detail

- **CVE-2020-25213** / advisory: primary advisory HTTP 403 (`https://plugins.trac.wordpress.org/changeset/2373068`, HTTP 403)
- **CVE-2024-10924** / advisory: primary advisory HTTP 202 (`https://www.wordfence.com/blog/2024/11/really-simple-security-vulnerability/`, HTTP 202)

## Notes

- Raw bytes are written verbatim; `sha256` is computed over the saved file and the
  `path` values are relative to this snapshot directory.
- `fetched_at_utc` is the wall-clock UTC time the response was received, per artifact.
- `nvd.json` is the unmodified NVD 2.0 API response; `cpe.json` is the extraction of the
  configurations/`cpeMatch` nodes (CPE names + version ranges) from that response.
- `advisory-fallback.*` is used only when the notes-recorded advisory URL is
  bot-blocked/unavailable; `advisory-primary.error.txt` keeps the failed response body
  for audit. Both cases are recorded in the failure list above.
- An advisory saved with HTTP 200 may still be an anti-bot page; check `http_status`,
  `final_url`, `bytes` and the file content before use.
