# Step 3 / Phase A — build report (cases, observations, advisory ranges)

Generated: 2026-10-17T15:41:17Z by `experiments/methods/build_inputs.py`.

## Case enumeration

- `n_unique_cves` = **32** (30 resolved + 2 Unresolved: CVE-2019-6341, CVE-2023-5631)
- `n_cases` = **69**
  - Applicable: 31
  - Not Applicable: 36
  - Unresolved: 2
- cases excluded from the metric denominator (Unresolved): 2

## Cases per CVE

| CVE | n_cases | labels |
|---|---|---|
| CVE-2021-41773 | 3 | Applicable, Not Applicable, Not Applicable |
| CVE-2019-6340 | 4 | Applicable, Applicable, Not Applicable, Not Applicable |
| CVE-2024-10924 | 3 | Applicable, Not Applicable, Not Applicable |
| CVE-2020-12625 | 2 | Applicable, Not Applicable |
| CVE-2014-3704 | 2 | Applicable, Not Applicable |
| CVE-2015-3440 | 2 | Applicable, Not Applicable |
| CVE-2017-1001000 | 2 | Applicable, Not Applicable |
| CVE-2018-7600 | 2 | Applicable, Not Applicable |
| CVE-2018-7602 | 2 | Applicable, Not Applicable |
| CVE-2019-10692 | 2 | Applicable, Not Applicable |
| CVE-2019-6341 | 1 | Unresolved |
| CVE-2019-8942 | 2 | Applicable, Not Applicable |
| CVE-2020-12640 | 3 | Not Applicable, Applicable, Not Applicable |
| CVE-2020-12641 | 3 | Not Applicable, Applicable, Not Applicable |
| CVE-2020-13671 | 3 | Not Applicable, Applicable, Not Applicable |
| CVE-2020-25213 | 2 | Applicable, Not Applicable |
| CVE-2021-23017 | 1 | Not Applicable |
| CVE-2021-24917 | 2 | Applicable, Not Applicable |
| CVE-2021-29447 | 2 | Applicable, Not Applicable |
| CVE-2021-42013 | 2 | Applicable, Not Applicable |
| CVE-2021-44026 | 2 | Applicable, Not Applicable |
| CVE-2022-21661 | 2 | Applicable, Not Applicable |
| CVE-2023-2745 | 2 | Applicable, Not Applicable |
| CVE-2023-28121 | 2 | Applicable, Not Applicable |
| CVE-2023-32243 | 2 | Applicable, Not Applicable |
| CVE-2023-3460 | 2 | Applicable, Not Applicable |
| CVE-2023-5631 | 1 | Unresolved |
| CVE-2023-5798 | 2 | Applicable, Not Applicable |
| CVE-2024-28000 | 2 | Applicable, Not Applicable |
| CVE-2024-37383 | 2 | Applicable, Not Applicable |
| CVE-2023-23752 | 2 | Applicable, Not Applicable |
| CVE-2023-6553 | 3 | Applicable, Applicable, Not Applicable |

## Observations

- accepted observation records: 59 (from 56 verified-probe requests; 3 additional condition(s) extracted from a shared response, R4)
- G7 (pending/needs_control -> Unknown) entries recorded: 77
- cases with at least one accepted observation: 37 / 69

## Advisory ranges

- non-null normalised ranges: 27
- null (no machine-readable range): CVE-2019-10692, CVE-2019-8942, CVE-2020-25213, CVE-2021-44026, CVE-2024-10924

All advisory quotes were verified against the frozen artifact bytes at build time.

## Artifact hashes (sha256 of the files as written)

| artifact | sha256 |
|---|---|
| `experiments/methods/data/cases.json` | `2edb0e5a4ff03ac894e506ecf9634cb57d589e24be822f52fe619f045f2dd1ae` |
| `experiments/methods/data/observations.json` | `f23917d381eab85a7b59e823250e69371453354e745a03c7b1db60ad67751bee` |
| `experiments/methods/data/advisory_ranges.json` | `70b57821353bf35421cb470c2857d05f222b43d1e47c70ab88212c5ef519bb7c` |
| `notes/collector-mapping-30cve.md` (D-030, amended D-032/D-033/D-034 + 2026-10-17 top-up = 32 CVE; freeze D-037 pending) | `c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c` |
| `data/public-snapshot/manifest.json` (frozen D-026, 2026-10-11 cohort) | `854853ec2ca083a1f779da22debc4413131fe3695aa32e2fff01649f1d227bf7` |
| `data/public-snapshot-2026-10-17/manifest.json` (D-035 top-up cohort) | `ae334955768e6cf18f6be14d7f2fabaaaa04dfd86558645f5cd23bed99353679` |

`generated_at_utc` is embedded in each JSON document, so re-running this script yields a different byte hash even when nothing else changes; the documents were compared with `generated_at_utc` stripped to establish semantic equality.

This build carries the **2026-10-17 top-up**: 2 mapping blocks merged (CVE-2023-23752, CVE-2023-6553) per `reviews/Review_mapping_topup_phanquyet_2026-10-17.md`, the 4 new probes `pending` -> `verified` from `experiments/topup-2026-10-17/cases/`, the 2 new advisory ranges (one of them parsed from the CVE.org CNA **JSON** record), and 5 new cases (2 Joomla + 3 Backup Migration, D-036). `cases.json` gains the 5 cases + counts; `observations.json` gains the new accepted observations; `advisory_ranges.json` gains the 2 entries. Nothing from the 30-CVE cohort/V1/V2 outputs changed.


### Previous build (V2, 2026-10-16), for traceability

| artifact | sha256 (previous) |
|---|---|
| `experiments/methods/data/cases.json` | `98dd5f6a1aa0709c952cf298a10c574da5eada7452dac01d4f33ca1e64829c1f` |
| `experiments/methods/data/observations.json` | `ba72d8071ddaa4a1fe990647793295f328e8de541bd66907108d65d9cad1a0a8` |
| `experiments/methods/data/advisory_ranges.json` | `32a51c8a8e4a2f0f22b6351f62f3554650a871e238c151de1464bbf3904c9f22` |