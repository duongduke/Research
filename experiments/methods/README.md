# `experiments/methods/` — step 3: five methods + evaluation harness (RQ-C1)

> Engineer deliverable for **step 3** of the method freeze (see
> `notes/method-implementation-spec-2026-10-15.md`).  Operates **only** on frozen
> inputs: `notes/collector-mapping-30cve.md` (D-030, amended by D-032/D-033/D-034 and by
> the 2026-10-17 top-up = 32 CVE blocks), `data/public-snapshot/` (D-026) +
> `data/public-snapshot-2026-10-17/` (D-035 top-up cohort), the frozen `advisory.*`
> bytes, and two engineer-produced inputs described below.
> **No frozen artifact was edited.**  The V1 comparison run (**step 4**) was
> performed **once** on 2026-10-15 (`output/benchmark/`, kept intact for comparison)
> and the V2 run **once** on 2026-10-16 (`output/benchmark-v2/`); see
> `NOTE-d032-2745-step4-2026-10-15.md` and
> `NOTE-v2-captures-benchmark-2026-10-16.md` for the raw result tables.
>
> **Fix round 2026-10-15 (engineer):** five implementation findings from
> `reviews/Review_buoc3_implementation_2026-10-15.md` §1 were fixed (status200
> predicate, fusion empty-range, fusion E4 independence, the two advisory
> encodings, `mode_check` no longer computing metrics) and the derived inputs were
> regenerated.  Details, new hashes and the fixture additions are in
> **`NOTE-fix-round-2026-10-15.md`**.
>
> **D-032 round + step 4, 2026-10-15 (engineer):** the accepted mapping amendment
> **D-032** (`CVE-2017-1001000.probe_rest_root` validation verified → pending) is
> synced into the loaders, `versioncmp.match_range` gained the `out_of_scope:
> "unknown"` key and the CVE-2023-2745 advisory range now uses it, the derived
> inputs were regenerated, the fixture grew to **161/161** checks, and **step 4
> (the real comparison run) was executed once**.  Details, hashes, the raw metric
> table and the flagged observations are in
> **`NOTE-d032-2745-step4-2026-10-15.md`**.
>
> **V2 round, 2026-10-16 (engineer):** the accepted mapping amendments **D-033**
> (two probe request paths corrected) and **D-034** (4 V2 captures → probes
> `verified`) are synced (`MAPPING_SHA256 = 9a43a0f2…`), the four V2 probes are
> wired into the observation extraction from `experiments/methods/captures-v2/`,
> the CVE-2024-10924 collector now emits **both** `p_2fa_enabled` and
> `p_skip_onboarding_route` from the **single** `probe_two_fa_route` response
> (R4: 2 extractions = 1 request), the derived inputs were regenerated (fixture
> **174/174**), and the **V2 benchmark** was run **once** into the separate
> `output/benchmark-v2/` directory (V1 `output/benchmark/` untouched).  Details,
> hashes, the raw metric table and the V1→V2 per-case delta are in
> **`NOTE-v2-captures-benchmark-2026-10-16.md`**.
>
> **Final hash sync, 2026-10-16 (engineer):** the two researcher edits to the mapping were
> **documentation-only** (`probe_um_register_form` `artifact_refs` realigned to the superseding
> `captures-v2/CVE-2023-3460/8831-um267-GET-page_id6-AS-SPECIFIED.txt` capture; a D-034 line
> added to the mapping header), so only the mapping sha256 changed.  `MAPPING_SHA256` in
> `build_inputs.py` + `harness.py` was synced to **`e8debc35…`**.  No condition/path/probe/
> `interpret`/`validation` semantics changed, so the three derived inputs were **not**
> regenerated and remain `cases.json 98dd5f6a…`, `observations.json ba72d807…`,
> `advisory_ranges.json 32a51c8a…`; the V2 benchmark was re-run once into
> `output/benchmark-v2/` and `metrics.json` / `predictions.json` are **byte-identical** to the
> previous V2 run (fusion TP 3 / FP 0 / TN 11, recall 0.1071, F1 0.1935).  Only
> `run-metadata.json`'s timestamp + mapping sha256 changed.  V1 `output/benchmark/` untouched.
>
> **Top-up round, 2026-10-17 (engineer):** the 2 top-up CVE blocks (CVE-2023-23752, CVE-2023-6553) were
> merged into the mapping per `reviews/Review_mapping_topup_phanquyet_2026-10-17.md` (paths reduced to the
> single accepted precondition each; 4 probes `verified` from the 2026-10-17 captures), the loaders accept
> the **second snapshot cohort** `data/public-snapshot-2026-10-17/` (both manifests verified on load) and a
> **JSON advisory branch** (CVE.org CNA `lessThanOrEqual` for CVE-2023-6553, fixed 1.3.8 recorded with
> changelog provenance), and the derived inputs were regenerated **once** (32 CVE / 69 cases; fixture
> **193/193**).  `MAPPING_SHA256` = **`c186250e…`**; **the benchmark was NOT run** — the 32-CVE freeze
> (D-037) is the next researcher step.

## Layout

```
experiments/methods/
├── build_inputs.py        # Phase A: builds the three method inputs from frozen artifacts
├── versioncmp.py          # version parsing + CPE/advisory range matching (pure)
├── methods.py             # the five methods (pure functions of mapping/snapshot/observations/ranges)
├── metrics.py             # D-026/D-027 R5 metric formulas (per case)
├── harness.py             # loader with hash checks, runner, scoring, run metadata
├── data/                  # Phase A outputs (inputs to the methods)
│   ├── cases.json             # M2 — case list + ground-truth labels (labels used only when scoring)
│   ├── observations.json      # M1 — accepted E5/E6 observations per case (verified probes only)
│   ├── advisory_ranges.json   # M3 — normalised advisory ranges (null where not machine-readable)
│   └── build-report.md        # Phase A report: counts, per-CVE case table, quote checks
├── fixture/               # Phase C: synthetic dataset + runner (same code path)
│   ├── fixture_mapping.md     # 12 fake CVEs, D-030 schema
│   ├── fixture_cases.json     # cases + expectations + a metric fixture
│   ├── fixture_observations.json
│   ├── fixture_advisory_ranges.json
│   ├── fixture_snapshot.json
│   ├── run_fixture.py         # 193 checks; exit 0 only if everything passes
│   └── output/                # fixture predictions/metrics/run metadata + fixture-report.json
└── output/                # load/check evidence (no benchmark result)
    ├── run-metadata.json      # `harness.py load`: mapping sha256 + snapshot manifest sha256 + counts
    ├── check/check-report.json# `harness.py check`: structural gate on the real inputs
    ├── benchmark/             # V1 benchmark (2026-10-15) — kept for comparison, do not overwrite
    └── benchmark-v2/          # V2 benchmark (2026-10-16) — D-033/D-034 evidence
```

## How to run

```bash
cd <repo>
python3 experiments/methods/build_inputs.py            # Phase A (rewrites data/*.json; --check verifies only)
python3 experiments/methods/fixture/run_fixture.py     # Phase C (must print 193/193 pass)
python3 experiments/methods/harness.py load            # hash checks + enumeration (safe)
python3 experiments/methods/harness.py check           # structural gate on the real inputs (no result emitted)
# each benchmark run goes to its own directory; never overwrite a previous run
python3 experiments/methods/harness.py benchmark --run-benchmark --out experiments/methods/output/benchmark-v2
```

`load` verifies: mapping sha256 = `c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c`
(D-030 as amended by D-032/D-033/D-034 and by the 2026-10-17 top-up; 32 CVE blocks; **freeze of the
32-CVE version = D-037, pending**) and **both** snapshot cohorts against their own `manifest.json`
(`data/public-snapshot` 92 hashed artifacts + `data/public-snapshot-2026-10-17` 7 hashed artifacts) —
a mismatch raises `HashMismatch` and nothing is produced.  Every cohort hash is recorded in
`run-metadata.json` under `snapshot.cohorts`.

## Method → rule mapping

| method | evidence used | rule source |
|---|---|---|
| `cpe_only` | `E1` from `cpe.json` (product-filtered) + `E5` | fusion-design §3.1 |
| `nvd_only` | `E1` from NVD `configurations` CPE (product-filtered) + `E2` metadata + `E5`; CNA `affected[]` recorded as provenance only | fusion-design §3.2, D-028 R1 |
| `advisory_only` | `E1` (normalised advisory range) + `E3` + `E4` + `E5`, in the §3.3 priority order (E4 patch linkage → missing data → outside range → in range with unobservable preconditions → Applicable) | fusion-design §3.3 |
| `http_version_only` | `E5` + the declared CPE lookup table (level 1 only) | fusion-design §3.4 |
| `fusion` | `E1`–`E6`, tiered; canonical `B` / `P_i` conclusion | fusion-design §4, §4.1, §4.2, §4.5 (+ D-027 R1/R2) |

Hard invariants implemented:

* **G7 runtime gate** — a probe produces True/False (or an E5 value) **only** when
  `validation.status == "verified"`; `pending`/`needs_control` → `Unknown`, whatever
  the capture says.  The fixture proves this with deliberately bogus values on a
  `pending` and a `needs_control` probe.
* **Source isolation** — each method reads only its own source; `cpe_only` never
  opens `nvd.json`, `nvd_only` never uses `cpe.json` or the CNA `affected[]`,
  `advisory_only` never borrows a CPE/NVD range.
* **Product scoping (B9)** — CPE/NVD ranges are filtered to the case product
  (`vendor:product`), and only `vulnerable != false` entries are used; product
  identity must itself come from accepted HTTP evidence, otherwise the level-1
  methods return `Unknown`.
* **B / P_i separation** — `B` = product identity + `version ∈ range` (precedence
  advisory > NVD > CPE for the same assertion+scope) + `E4` patch linkage;
  `P_i` = all-of the `kind: precondition` conditions of impact path `i`.
  Branch **b** (config-blocked) requires a determined path scope and every path
  `P_i = False` — it does **not** require `B = True`; branch **a** is `B = False`.
  `kind: build` conditions never enter `P_i` (G1).
* **Missing data / conflict is never a negative** — undecidable bounds, a missing
  range record, an unidentified product or an unresolved same-tier NVD/CPE conflict
  all yield `Unknown`.
* **Label isolation** — methods receive a label-free, build-free, config-free case
  view (`harness.case_view` allowlist: `case_id`, `cve_id`, `product_key`,
  `cpe_vendor_product`, `identity_tokens`, `identity_family`); `methods._assert_label_free`
  raises if a label key ever leaks in.  Labels are joined only in `metrics.evaluate`.
* **No fallback to ground truth** anywhere.

## Decisions taken in this implementation (documented, not silent)

1. **Version comparison** (`versioncmp.py`): `release` mode = numeric dotted release
   (`5.0 == 5.0.0`, `1.10 > 1.9`); pre-release suffixes (`-rc1`, `-src`, …) sort
   below the plain release; packaging/distro revisions (`-6ubuntu9`) sort above it
   but a bare upstream version and a revisioned version are **not comparable**
   (`scope_mismatch`) — range matching returns `None`, i.e. the method abstains
   (mechanical R2).  `lex` mode exists for sources that declare lexicographic order.
   CPE `update`/`edition` components are ignored for level-1 matching (the observed
   HTTP token is a plain release token); the CPE `version` component is matched
   exactly (`strict_exact`).
2. **Advisory range normalisation** — each CVE gets a normalised list of range dicts
   plus verbatim quotes that are **verified against the frozen artifact bytes** at
   build time (`extraction_kind`: `affected_versions_block`, `body_sentence`,
   `title_fixed_in`, `fixed_release_statement`, `fixed_version_list`,
   `fixed_version_table`, or `none`).  `null` for the five CVEs the spec names.
   `CVE-2017-1001000` is **not** null: the post has no "Affected versions" block, but
   its body sentence names `4.7` and `4.7.1` explicitly, so the range is the union of
   those two exact releases (quote recorded).  ⚠ the researcher should confirm this
   input decision — see `REPORT-step3.md` "decisions to confirm".
3. **Product identity** — the case carries the CPE `vendor:product` keys for its
   product (collector identity metadata, from `registry.md` product names + the
   snapshot's CPE tokens).  A level-1 conclusion additionally requires an accepted
   (verified) identity observation whose text matches the case's `identity_tokens`
   (plus `identity_family` for Drupal 7 vs 8).
4. **`observations.json`** records one entry per (case, probe) — plus one extra entry
   per *additional condition* a single response carries (the CVE-2024-10924 route
   probe decides both `p_2fa_enabled` and `p_skip_onboarding_route`; R4: 2 extractions
   = 1 request, no second probe).  Verified probes carry the observed value + the
   exact artifact line + extraction rule; `pending`/`needs_control` probes carry
   `observed: null`.  Captures come from the probe artifacts and (since D-034) from
   `experiments/methods/captures-v2/`.  Nothing is extracted from PoC
   logs, DB dumps, attacker listeners, `dpkg -l`, image digests or archive hashes.
   The 5798 "negative observability" probe is recorded as `negative_observability`
   (`predicate_value: null`) so `E5` stays unknown.
5. **Fusion precedence** — advisory > NVD > CPE for the same assertion + scope
   (D-019 §4.1); a disagreement is **reported** in `evidence.tier2_source_verdicts`
   rather than hidden.  A same-tier NVD/CPE disagreement with no advisory to break
   the tie is an unresolved conflict → `Unknown`.
6. **`E4` patch linkage** is evaluated **first** and independently of the version/range
   tiers: a verified patch condition that is True sets `B = False` (branch a) even when
   the version is hidden or no source has a range scoped to the product; a distro fix
   that is not linked to the observed target is **not** patch evidence.
   Conversely, a **missing** range (e.g. the product filter removed every entry) is
   missing data, never "outside the range" → `B = Unknown`.
7. **Metric policy** — see `metrics.py`: `Unresolved` cases are excluded from `N` and
   reported separately; `N/A` on a zero denominator; `F1 = 0` when `TP = 0` and the
   denominator is positive; `U_A` stays in the recall/F1 denominators.
8. **Benchmark gate** — `harness.py benchmark` refuses to run without
   `--run-benchmark`; `harness.py check` executes the methods on the real inputs but
   asserts invariants only, calls **no** metric code and emits no predictions/metrics
   (`metrics_computed: false`).

## What this directory deliberately does not do

* No live network access, no re-fetching of CVE data, no lab/VM activity.
* No tuning of cutoffs, ranges, mapping or thresholds after seeing any prediction:
  the fixture is the only place where predictions were inspected in aggregate.
  (The 2026-10-15 fix round compared per-case *predictions* between the pre-fix and
  post-fix states in a scratch directory to confirm the intended effect — no metric
  was computed and no case was re-labelled; see `NOTE-fix-round-2026-10-15.md` §6.)
* No edit of `notes/` (mapping/spec/decisions), `data/public-snapshot/`,
  `experiments/26cve/` (registry/selection-log/case READMEs) or the pilot artifacts.
