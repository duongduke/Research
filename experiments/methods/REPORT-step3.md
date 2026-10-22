# Step 3 report — five methods + evaluation harness (RQ-C1)

> Engineer (DeepSeek V4.1 Flash) deliverable for **step 3** of
> `notes/method-implementation-spec-2026-10-15.md`, per
> `reviews/Xac_nhan_ban_khoa_mapping_D030_2026-10-14.md` §"Chuyển sang bước 3".
> Status: **implementation complete; the real comparison (step 4) has NOT been run.**
> No frozen artifact was edited; no methodology decision was taken.
> All outputs live under `experiments/methods/`.
>
> **Superseded in part (2026-10-15):** this report describes the step-3 delivery
> *before* the five-finding fix round.  Where it states that `harness.py check`
> computes no metrics, that is true of the current code but was **not** true of the
> code this report was written against (see review finding 5).  Current state, new
> input hashes and the extended fixture (143/143) are in
> **`NOTE-fix-round-2026-10-15.md`**.  Nothing else in this report has been altered.

Date of run: 2026-10-15 (workspace clock).  Mapping sha256
`f266673ee3f1b2d6ae14b0ac2357a550d63a4013b4eb7f1e8676509248d7fbd1` (D-030) verified on
load; snapshot verified against `data/public-snapshot/manifest.json`
(`manifest.json` sha256 `854853ec2ca083a1f779da22debc4413131fe3695aa32e2fff01649f1d227bf7`,
92 hashed artifacts, 0 mismatches, 0 missing, 0 unlisted).

---

## Phase A — data preparation (cases / observations / advisory ranges)

### Case enumeration (deliverable a)

| count | value |
|---|---|
| `n_unique_cves` | **30** (28 resolved + 2 Unresolved: `CVE-2019-6341`, `CVE-2023-5631`) |
| `n_cases` | **64** |
| labels | Applicable **28**, Not Applicable **34**, Unresolved **2** |
| branch split | branch a **28**, branch b **6**, Unresolved **2**, Applicable **28** |
| cases excluded from the metric denominator | 2 (the Unresolved cases) |

*"28 resolved" is the number of resolved **CVE IDs**, not cases* — `n_unique_cves`,
`n_cases` and the label histogram are reported separately, as required.

Cases per CVE (64 total):

| pattern | CVEs | cases |
|---|---|---|
| vuln + fixed pair | 21 CVEs — 2014-3704, 2015-3440, 2017-1001000, 2018-7600, 2018-7602, 2019-10692, 2019-8942, 2020-12625, 2020-25213, 2021-24917, 2021-29447, 2021-42013, 2021-44026, 2022-21661, 2023-2745, 2023-28121, 2023-32243, 2023-3460, 2023-5798, 2024-28000, 2024-37383 | 42 |
| config-gated: config-off = NA-b, config-on vuln = Applicable, config-on fixed = NA-a | 2020-13671, 2020-12640, 2020-12641 | 9 |
| pilot Drupal 8.6 (REST on / REST off + JSON:API on / both off / fixed REST on) | 2019-6340 | 4 |
| pilot WordPress plugin (2FA on / 2FA off / fixed 2FA on) | 2024-10924 | 3 |
| pilot Apache (weakened 2.4.49 / default 2.4.49 / fixed 2.4.51) | 2021-41773 | 3 |
| backport, single state (NA-a) | 2021-23017 | 1 |
| Unresolved, single registry row | 2019-6341, 2023-5631 | 2 |

Branch-b (config-blocked) cases: `CVE-2021-41773__default_249`,
`CVE-2019-6340__both_off_869`, `CVE-2024-10924__9_1_1_1_2fa_off`,
`CVE-2020-13671__config_off`, `CVE-2020-12640__config_off`, `CVE-2020-12641__config_off`.

Labels were **transcribed, never created**: each case carries a `label_source`
pointing at the registry row / per-case README section / pilot README row that
established it (`data/cases.json`).  `D-020…D-024` deviations are carried into the
case notes (e.g. CVE-2020-25213 fixed control 8.0.6 instead of the unavailable 6.9 zip;
CVE-2018-7602 labelled on the Drupal 7 7.58/7.59 pair; the two XSS CVEs Unresolved).

### Label-source notes / judgement calls (deliverable a: "ambiguous label source")

1. **CVE-2021-41773 (3 cases)** — the pilot repro README states per-state HTTP
   outcomes (200 + marker on the weakened 2.4.49; 403 on default 2.4.49; 404/400 on
   2.4.51) and then the one-line interpretation ("affected version does not by itself
   imply applicable/exploitable in this configuration").  The three labels
   (Applicable / NA-b / NA-a) follow from the protocol's branch rules applied to those
   outcomes, **not** from a per-state label table.  Transcribed as the accepted reading;
   if the researcher prefers to count only the weakened/fixed pair, `n_cases` changes.
2. **CVE-2019-6341 and CVE-2023-5631** — the registry carries **one row** per CVE with a
   single `Unresolved` label, although a fixed-control state was observed in both
   READMEs.  I transcribed **one case each** (Unresolved) rather than inventing a second
   Unresolved case.  This affects `n_cases` only (Unresolved cases are outside the
   metric denominator).
3. **CVE-2015-3440** — the case README labels the deployment "WP 4.2.0" while the frozen
   capture and control ids use `4.2-src`; recorded as `vuln_build = "4.2-src (deployment
   labelled WP 4.2.0)"`.  The label itself is unambiguous.
4. **CVE-2021-23017** — one case (NA-a) with no affected-build control exists; that is the
   accepted D-020 design, not a missing case.
5. **CVE-2020-13671 / 12640 / 12641 config-on Applicable cases** — the positive state was
   established with a **simulated** installer/fixture step (planted file / config-on), as
   the case READMEs and the protocol's simulation note describe; recorded in the case
   notes.

### Observations (`observations.json`)

Extracted **only** from probes whose `validation.status == "verified"` in the frozen
mapping, and only from the frozen HTTP captures the mapping references.

| fact | value |
|---|---|
| verified probes in the mapping (D-030) | 18 |
| case-level observations recorded from them | **39** |
| G7 entries recorded (`pending` / `needs_control` → `observed: null`) | **84** |
| cases with ≥1 accepted observation | **30 / 64** |

Each observation records `artifact_ref`, `artifact_section`, the exact `artifact_line`,
the extraction rule, the observed value, and the predicate value + reason.  Excluded by
policy: PoC/exploit logs, DB dumps, attacker-listener logs, `dpkg -l`/package metadata,
image digests, archive hashes.

Consequence to be aware of before step 4 (derivable from the frozen data, not from a run):
all five methods need an accepted identity/version observation before any level-1
conclusion; **34 of 64 cases have no accepted observation for their product/version**
(Drupal family-only fingerprints, all Roundcube and several plugin cases are
`pending`/`needs_control` in the frozen mapping).  Those cases are `Unknown` **by
construction** of G7, not by method failure.  `CVE-2021-23017` is the explicitly
intended case of this kind (D-020.2/B1: method output remains `Unknown`).

### Advisory ranges (`advisory_ranges.json`)

| extraction kind | n CVEs |
|---|---|
| `affected_versions_block` (explicit affected list) | 11 |
| `fixed_release_statement` (fixed release named, no affected block) | 4 |
| `fixed_version_list` (per-branch fixed releases listed) | 4 |
| `title_fixed_in` | 3 |
| `body_sentence` | 2 |
| `fixed_version_table` (distro per-release fixed revisions) | 1 |
| `none` → `ranges: null` | **5** — `CVE-2019-8942`, `CVE-2019-10692`, `CVE-2020-25213`, `CVE-2021-44026`, `CVE-2024-10924` |

Every recorded quote was verified verbatim (whitespace-tolerant) against the frozen
advisory bytes at build time; a missing quote aborts the build.  `CVE-2019-10692`
additionally records a **negative check** (`"7.11.17"`, `"7.11.18"` asserted absent
from the frozen artifact).

---

## Phase B — implementation

Files: `versioncmp.py`, `methods.py`, `metrics.py`, `harness.py` (see `README.md` for the
method→rule mapping and the invariants).  All methods are pure functions of
`(mapping, snapshot, observations, ranges)`; the fixture calls the same functions.

* **Hash check on load** — mapping sha256 vs D-030 and the snapshot manifest are
  verified; a mismatch raises `HashMismatch` and produces nothing.  Both hashes are
  recorded in `run-metadata.json` (mapping sha256, snapshot manifest sha256, snapshot
  verification output, snapshot date, per-input sha256 of `cases.json`,
  `observations.json`, `advisory_ranges.json`).
* **Source isolation / product scoping / B-P_i separation / G7 gate / label isolation**
  — enforced in code (fixture-tested) as described in `README.md`.
* **Scoring** — `metrics.py` implements the D-026/D-027 R5 formulas per case,
  `Unresolved` excluded and reported separately, `N/A` on zero denominators,
  duplicate prediction vectors reported in `metrics.json`.

### Rule-conformance spot checks (not a benchmark result)

Run through `harness.py check` (invariants only) plus targeted assertions:

* `CVE-2021-23017` (backport) → `Unknown` for all five methods (B1/D-020.2: the header
  cannot confirm the package revision) ✔.
* `CVE-2017-1001000` fixed build (`4.7.2`) → `cpe_only` Applicable (CPE lists 4.7.2 as
  vulnerable, B10 — the measured false positive), `advisory_only` Not Applicable,
  `fusion` Not Applicable **via advisory precedence**, with the source disagreement
  recorded in `evidence.tier2_source_verdicts` ✔.
* Config-blocked pilot cases (`CVE-2021-41773__default_249`, `…__weakened_249`) →
  `fusion` returns `Unknown` with `B=True` and `P_i=Unknown`, because the frozen mapping
  declares both traversal preconditions `observable: false` (no probe) — i.e. the
  "fusion decides the config case" story is **not** reachable with the current evidence
  set; the honest output is `Unknown`.  Same pattern for the other config-blocked cases
  whose gating probe is `pending`.
* `harness.py check` on the real inputs: 64 cases × 5 methods = 320 records, every
  prediction in `{Applicable, Not Applicable, Unknown}`, predictions invariant under a
  ground-truth label swap, every record carries reasons/evidence/provenance.
  **No predictions or metrics were written for the benchmark** (`benchmark_result_written: false`).

---

## Phase C — synthetic fixture (must pass before step 4)

`python3 experiments/methods/fixture/run_fixture.py` → **112/112 checks pass**.

| property | how it is exercised | result |
|---|---|---|
| (a) inclusive / exclusive / exact boundaries | `CVE-9000-0001` (2.0≤v<3.0 incl./excl.), `CVE-9000-0002` (exact `1.4`), plus `versioncmp` units (`1.10>1.9` numeric vs lexicographic, `1.0-rc1 < 1.0`, zero-padding equality) | pass |
| (b) product + source filtering | `CVE-9000-0002` decoy `other:thing` entry that is `vulnerable:false` and would otherwise match; unidentified-product case | pass |
| (c) B / P_i + Unknown gate | NA-b with `B=Unknown` (branch b needs no `B=True`); branch a with `B=False`; **G7**: a `pending` and a `needs_control` probe carrying a *bogus* True value must not decide the predicate → `Unknown`; same-tier NVD/CPE conflict → `Unknown`; missing range record → `Unknown`; E4 patch linkage → `B=False`; empty impact path → `P_i=True` | pass |
| (d) label isolation | identical predictions after swapping every label; runtime guard `methods._assert_label_free` rejects a labelled case view | pass |
| (e) metrics with `U_A` and zero denominator | `metric_fixture`: `mixed` (TP1/FP1/TN0/FN1/U_A1/U_N1 → precision 0.5, recall 1/3, F1 0.4, coverage 0.6, Unknown rate 0.4); `all_unknown` (precision `N/A`, recall 0, F1 0, coverage 0, Unknown rate 1); `all_negative`; Unresolved excluded from `N`; duplicate vectors reported ('all_unknown' ≡ 'all_unknown_copy') | pass |
| (f) hash mismatch | frozen mapping loads with the recorded sha256; a tampered mapping copy → hard fail; wrong block count → hard fail; a clean one-CVE slice of the frozen snapshot verifies; the same slice with one tampered byte → hard fail | pass |

Fixture outputs: `fixture/output/{predictions.json,metrics.json,run-metadata.json,fixture-report.json}`.
The fixture is the **only** dataset whose predictions were inspected in aggregate.

---

## Phase D — deliverables, files, and what I could not determine

### File list

| path | role |
|---|---|
| `experiments/methods/README.md` | design, rule mapping, invariants, decisions, how to run |
| `experiments/methods/REPORT-step3.md` | this report |
| `experiments/methods/build_inputs.py` | Phase A builder (hash-verified mapping loader, quote checks) |
| `experiments/methods/versioncmp.py` | version parsing + range matching |
| `experiments/methods/methods.py` | the five methods |
| `experiments/methods/metrics.py` | metric formulas |
| `experiments/methods/harness.py` | loader (hash checks) + runner + scorer + run metadata |
| `experiments/methods/data/cases.json` | M2 — 64 cases + labels + label sources |
| `experiments/methods/data/observations.json` | M1 — accepted observations (39) + G7 entries (84) |
| `experiments/methods/data/advisory_ranges.json` | M3 — normalised advisory ranges (25 non-null, 5 null) |
| `experiments/methods/data/build-report.md` | Phase A report |
| `experiments/methods/fixture/*` | synthetic fixture (mapping, cases, observations, ranges, snapshot, runner) |
| `experiments/methods/fixture/output/*` | fixture predictions/metrics/run metadata/report |
| `experiments/methods/output/run-metadata.json` | `harness.py load` evidence (hashes + counts, no predictions) |
| `experiments/methods/output/check/check-report.json` | `harness.py check` structural gate (no result) |

No file outside `experiments/methods/` was created or modified.

### Decisions to confirm before step 4 (things I had to decide as the implementer)

1. **`CVE-2017-1001000` advisory range is not null.**  The spec's null list names five
   CVEs and does not include this one, but the mapping's advisory literal says the post
   has no machine-readable affected-version block.  The frozen advisory *does* state in
   its body text: "WordPress 4.7 and 4.7.1 had one additional vulnerability …", so I
   encoded the union of the two exact releases with that quote as evidence
   (`extraction_kind: body_sentence`).  Effect: `advisory_only`/`fusion` can resolve the
   wrong-CPE case (B10) through precedence.  If the researcher prefers `null` here, the
   change is one entry in `data/advisory_ranges.json` (and step 4 must be re-run after
   that edit — no tuning happened, nothing was inspected in aggregate).
2. **`CVE-2021-23017` advisory range** is distro-scoped (`lt 1.18.0-6ubuntu9`, from the
   Ubuntu page's per-release "Fixed" table) with an explicit `scope_note`; the spec's
   null list does not include it.  It has no effect in this benchmark (E5 is not
   accepted for that case → all methods `Unknown`), but the shape should be confirmed
   as the intended reading of "advisory range" for distro advisories.
3. **`CVE-2023-5631` advisory range covers only the 1.6 line** (`1.6.0 ≤ v < 1.6.4`)
   because the frozen news page is the 1.6.4 release note; it therefore cannot cover the
   1.4.11 case build.  Recorded, not repaired (the CVE is Unresolved and outside the
   denominator).
4. **Product keys** (`cpe_vendor_product`) are collector identity metadata carried per
   case (from the registry product names and the snapshot's CPE tokens).  They are
   required for spec §4.1 product scoping; a level-1 conclusion additionally requires an
   accepted identity observation matching the case's `identity_tokens`.
5. **Unresolved cases** are represented as one case each (see Phase A note 2).
6. **`CVE-2021-41773` case split** (3 cases incl. the default-config NA-b case) is a
   derivation from the pilot README interpretation (Phase A note 1).

### Findings about the frozen inputs (facts, not rule changes)

* The mapping literal for `CVE-2021-41773` attributes "This issue only affects Apache
  2.4.49 and Apache 2.4.50 and not earlier versions." to the 41773 entry, while the
  frozen httpd page places that sentence in the **42013** entry (the 41773 entry reads
  "… only affects Apache 2.4.49 …").  I parsed the artifact entry-scoped, so 41773 →
  `{2.4.49}` and 42013 → `{2.4.49, 2.4.50}` (identical to the mapping's ranges; only the
  quoted sentence differs).
* The mapping literal for `CVE-2024-28000` quotes "Vulnerable version(s) 6.3.0.1" /
  "Patched version 6.4"; the flattened Patchstack page emits the **values before their
  labels** ("… <= 6.3.0.1 Vulnerable version(s) 6.4 Patched version …").  The range is
  unchanged; recorded as a cross-check note in `advisory_ranges.json`.
* Two CVEs (`CVE-2017-1001000`, `CVE-2021-41773`) enumerate exact CPE versions with no
  `versionStart*/versionEnd*` bounds → handled by `strict_exact` equality; **the CPE
  entry that lists 4.7.2 as vulnerable is kept as-is** (measured false positive, B10).

### What I could not determine / did not do

* **The real comparison (step 4)** — not run, per the brief.  `harness.py benchmark`
  requires the explicit `--run-benchmark` flag.
* **Whether the researcher accepts the six decisions above** — they need an explicit
  ruling before step 4 (item 1 and item 6 can change per-case outcomes / case counts).
* **`CVE-2019-6340` has no version/identity probe at all** in the frozen mapping, so all
  four of its cases are `Unknown` for all five methods (product never identified from
  accepted evidence).  I did not add a probe (that would be new evidence collection, and
  B5 keeps the route probes `pending`).
* **Config-blocked pilot cases cannot be concluded by fusion** while the gating
  preconditions stay `observable: false` / `pending` in the frozen mapping (the lab did
  observe config state, but not as an accepted HTTP probe).  This is a data-coverage
  consequence, reported here so it is a known property of step 4 rather than a surprise.
* **I did not verify the semantic content of the 39 accepted captures by re-reading every
  artifact line** beyond the automated extraction assertions (each extraction fails
  loudly if its line is absent); the mapping's `verified` decisions are the researcher's
  (step 2) ruling and were taken as given.
* **Context files (`context/CURRENT_STATE.md`, `DECISIONS.md`, `TODO.md`) were not
  edited** — recording step 3 there is left to the researcher.
