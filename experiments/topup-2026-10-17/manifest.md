# Manifest — top-up cohort (CVE-2023-23752, CVE-2023-6553), fetched 2026-10-17

> **What this is:** durable copy of the step-1 verification artifacts (advisory +
> download) for the two top-up CVEs accepted in **D-035**. This is **not** ground
> truth and **no label** exists for either CVE. Nothing here was produced by
> reproduction — no container was built, no PoC was sent.
>
> **Provenance of the table values:** source URL / HTTP status / fetch date / byte
> size / sha256 of the four zips are the values recorded in
> `notes/cve-verification-topup-2026-10-17.md` §1.2 and §2.2. All hashes and sizes
> were **re-computed locally on the persisted copies** (`sha256sum`, `stat`) and
> matched; see §5. For the advisory/NVD/CVE.org files the report records URL + HTTP
> status but **no per-file timestamp or hash** — those were computed here and are
> marked accordingly.

## 1. Downloads (read-only evidence, do not edit)

| file | source URL | fetch (UTC) | HTTP | bytes | sha256 | notes |
|---|---|---|---|---|---|---|
| `downloads/Joomla_4.2.7-Stable-Full_Package.zip` | `https://downloads.joomla.org/cms/joomla4/4-2-7/Joomla_4.2.7-Stable-Full_Package.zip?format=zip` | 2026-10-17T13:57:40Z | 200 | 30,098,626 | `557d7414d05de0b27900a0d94423a84b2787dfec4b252b833040becd2ccc3349` | official CDN (redirect 302 → signed S3 URL); `unzip -tq` OK |
| `downloads/Joomla_4.2.8-Stable-Full_Package.zip` | `https://downloads.joomla.org/cms/joomla4/4-2-8/Joomla_4.2.8-Stable-Full_Package.zip?format=zip` | 2026-10-17T13:57:47Z | 200 | 30,119,992 | `d70ceb391d28355160d94338eaecaed2604c48f3472ee60493cf37f26f50fa44` | official CDN; `unzip -tq` OK |
| `downloads/bb-1.3.7.zip` | `https://downloads.wordpress.org/plugin/backup-backup.1.3.7.zip` | 2026-10-17T13:49:07Z | 200 | 1,002,720 | `bdd399bf6abdb27b35fdc2e3ebbf7eda044d9d03e7c9ebe829f9da4c51e48f0c` | wordpress.org plugin directory; `unzip -tq` OK |
| `downloads/bb-1.3.8.zip` | `https://downloads.wordpress.org/plugin/backup-backup.1.3.8.zip` | 2026-10-17T13:49:11Z | 200 | 1,003,073 | `f8c98d4696e76a09a8cf7df873ca8017131a53b702bef915bbc2966568574e44` | wordpress.org plugin directory; `unzip -tq` OK |

**Filename note:** the scratch copies were named `Joomla_4.2.7.zip` /
`Joomla_4.2.8.zip`; they are persisted here under the URL basename
(`Joomla_4.2.7-Stable-Full_Package.zip` / `…4.2.8…`). **Bytes are unchanged** — the
hashes above are the report's hashes and were re-verified after copying. The
`bb-*.zip` names already matched the URL basenames.

Independent size cross-check (report §1.2, re-read here from the persisted API
responses): GitHub Releases `4.2.7` asset `Joomla_4.2.7-Stable-Full_Package.zip` =
30,098,626 bytes and `4.2.8` = 30,119,992 bytes — identical to the downloaded
files. Same size from two independent hosts; the bytes were **not** compared
beyond size and CRC.

## 2. Primary sources (advisory / NVD / CVE.org)

`†` = fetch time is the preserved **file mtime in UTC**, not an independently logged
HTTP timestamp. Corroboration: for the four zips the same mtime convention
reproduces the report's recorded fetch times **exactly** (13:57:40Z, 13:57:47Z,
13:49:07Z, 13:49:11Z), so mtime is being read as the local write time of the fetch.

| file | source URL | fetch (UTC) | HTTP | bytes | sha256 |
|---|---|---|---|---|---|
| `sources/joomla-advisory.html` | `https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html` | 2026-10-17T13:48:38Z † | 200 | 34,126 | `41b8014857705f46ac51f74f63224bec6194285cedb65708fb197130b116877d` |
| `sources/CVE-2023-23752.nvd.json` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-23752` | 2026-10-17T13:48:31Z † | 200 | 3,518 | `290310c5f4e5ea8e650efd98b1442baac1baaeb926f1555acafa1796d95608a2` |
| `sources/cveorg-23752.json` | `https://cveawg.mitre.org/api/cve/CVE-2023-23752` | 2026-10-17T13:48:50Z † | 200 | 3,402 | `6c7b1d35ff92759b80a9ae00ce12387890ff89b770e345d8c2e34a549be7f95e` |
| `sources/CVE-2023-6553.nvd.json` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-6553` | 2026-10-17T13:48:32Z † | 200 | 5,843 | `9ba740dd5e4851308af18a4347a73bce79723cb74c5f7eb5134ea5c3547bb744` |
| `sources/cveorg-6553.json` | `https://cveawg.mitre.org/api/cve/CVE-2023-6553` | 2026-10-17T13:48:49Z † | 200 | 4,227 | `b4b39c29adec6d9034aa55c2bdfd4f9233ee88792e8ba50b131a947520ddbea2` |
| `sources/wpscan-6553.html` | `https://wpscan.com/vulnerability/6a4d0af9-e1cd-4a69-a56c-3c009e207eca` | 2026-10-17T13:48:51Z † | **403** | 7,355 | `b4b94e6496f82953c3c9d3d25bb482409d0204bf741e0db198b944bfe1409172` |

Notes on the two content-level checks done here (no interpretation added):

- The NVD files are the NVD 2.0 API envelopes: `CVE-2023-23752` → `vulnStatus: Analyzed`;
  `CVE-2023-6553` → `vulnStatus: Modified` (matches report §2.1).
- The CVE.org files are the 5.x CNA records: `cveMetadata.state = PUBLISHED`,
  assigner `Joomla` / `Wordfence` (matches report §1.1 / §2.1).
- `wpscan-6553.html` is the **bot-challenge page** (`<title>Checking your browser…</title>`,
  `/__challenge/probes.js`), i.e. it contains **no advisory text**. It is byte-identical
  (same sha256) to the scratch `wpscan-search.html`. This is consistent with the report's
  "403 (JS challenge)"; it is persisted as evidence of the block, **not** as an advisory
  source. The report's "Fixed in 1.3.8" WPScan statement rests on a search-index snippet
  and is not verifiable from this file.

## 3. Blocked / failed sources (recorded, not fabricated)

| artifact | source URL | fetch (UTC) | HTTP | bytes | sha256 | disposition |
|---|---|---|---|---|---|---|
| `wordfence-6553.html` (**not persisted**) | `https://www.wordfence.com/threat-intel/vulnerabilities/id/3511ba64-56a3-43d7-8ab8-c6e40e3b686e` | 2026-10-17T13:48:38Z † | **202** | 0 | — (empty file; sha256 of empty = `e3b0c442…b855`) | Cloudflare challenge, 0-byte body → **blocked**; not copied into this directory (nothing to preserve beyond the 0-byte fact). Report §2.1. |
| `sources/kev.json` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 2026-10-17T13:58:49Z † | **403** | 456 | `ff123e9604f0ce796a6c2ef0abcaf22c871a5fb74029c76d9ebd2ff54677a7f6` | Akamai "Access Denied" HTML → **not valid JSON**, never used. **CISA KEV membership of CVE-2023-23752 is therefore UNCONFIRMED** (NVD carries a reference pointing at KEV; that is not independent confirmation). Report §1.1, D-035. |
| GitHub release `.zip` (4.2.7) | `https://github.com/joomla/joomla-cms/releases/download/4.2.7/Joomla_4.2.7-Stable-Full_Package.zip` | — | 200, then **timeout @240 s** | 11,876,495 / 30,098,626 received | — | partial download deleted by the step-1 run; **no artifact exists**, so none is persisted. Report §1.2. |
| GitHub release `.zip` (4.2.8) | `https://github.com/joomla/joomla-cms/releases/download/4.2.8/Joomla_4.2.8-Stable-Full_Package.zip` | — | 200, then **timeout @240 s** | 13,064,516 / 30,119,992 received | — | same as above. Report §1.2. |

Neither zips nor any other artifact was re-downloaded or repaired in this
persistence step — the four downloads above are the step-1 files.

## 4. Auxiliary artifacts (persisted because the report cites them)

| file | source URL | fetch (UTC) | HTTP | bytes | sha256 | use |
|---|---|---|---|---|---|---|
| `sources/gh-4.2.7.json` | `https://api.github.com/repos/joomla/joomla-cms/releases/tags/4.2.7` | 2026-10-17T13:49:00Z † | 200 | 13,750 | `29633bed5c67773694b9c7ae0cb066980ebadc12d52aa9a116e6fd8cf736664d` | release-asset **size** cross-check (report §1.2) |
| `sources/gh-4.2.8.json` | `https://api.github.com/repos/joomla/joomla-cms/releases/tags/4.2.8` | 2026-10-17T13:49:00Z † | 200 | 13,441 | `49f595c586f6c86999de1c485e16808fb62ece6e91b3416ac2389ec8aeebaa09` | release-asset **size** cross-check (report §1.2) |

## 5. Re-verification log (run in this persistence step)

Commands and results on the **persisted** copies
(`experiments/topup-2026-10-17/`):

```bash
cd experiments/topup-2026-10-17
sha256sum downloads/*          # 4/4 match the report exactly
stat -c '%n %s' downloads/*    # 4/4 byte counts match the report exactly
for z in downloads/*.zip; do unzip -tq "$z"; done   # 4/4 "No errors detected"
sha256sum sources/*            # computed here; recorded in §2/§3/§4
```

| artifact | report sha256 | recomputed sha256 | match |
|---|---|---|---|
| `Joomla_4.2.7-Stable-Full_Package.zip` | `557d7414…cc3349` | `557d7414…cc3349` | **YES** |
| `Joomla_4.2.8-Stable-Full_Package.zip` | `d70ceb39…50fa44` | `d70ceb39…50fa44` | **YES** |
| `bb-1.3.7.zip` | `bdd399bf…e48f0c` | `bdd399bf…e48f0c` | **YES** |
| `bb-1.3.8.zip` | `f8c98d46…574e44` | `f8c98d46…574e44` | **YES** |

The table abbreviates only the display of identical 64-hex values; the full hashes are
in §1 (and in the step-1 report), and the comparison was done on the full strings
(`sha256sum` output vs report text), not on the prefixes.

**No mismatch.** Byte sizes also match exactly, and the preserved mtimes equal
the report's recorded fetch timestamps. Nothing was renamed *and* altered, no
partial/merged file exists here, and no file was overwritten.

Cross-check inside the packages (done from the persisted zips, not from the
scratch extraction trees):

- `administrator/manifests/files/joomla.xml` → `<version>4.2.7</version>` / `<version>4.2.8</version>`
  (as recorded in report §1.2).
- `libraries/src/Version.php` differs between the two zips (version bump).
- `backup-backup/backup-backup.php` → `Version: 1.3.7` / `Version: 1.3.8`;
  `readme.txt` → `Stable tag: 1.3.7` / `Stable tag: 1.3.8` (report §2.2).

## 6. Scope reminders

- No **ground-truth label** is assigned to either CVE (D-035). Resolved count stays **28**
  of 30 pre-top-up IDs; the top-up gives **32 distinct CVE IDs** with **2 Unresolved**
  (CVE-2023-5631, CVE-2019-6341) still manual-pending.
- These artifacts do **not** enter `data/public-snapshot/`: they are a **separate
  cohort** with a 2026-10-17 fetch date (D-035 §5). The 2026-10-11 snapshot and the
  V1/V2 benchmark outputs were not touched.
- The code reading behind `fix-diff.md` used these zips only; **nothing was executed**.
