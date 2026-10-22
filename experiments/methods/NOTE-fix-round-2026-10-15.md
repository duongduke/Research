# Fix round 2026-10-15 — 5 implementation findings (engineer, step 3)

> Scope: code + derived method inputs only. Source of the findings:
> `reviews/Review_buoc3_implementation_2026-10-15.md` §1 (findings 1–5) + §4 (fix plan).
> **No frozen artifact was edited**; **no benchmark / metric was run** (step 4 stays gated).

## 1. What was changed

| # | File | Before | After (exact new behaviour) |
|---|---|---|---|
| 1 | `build_inputs.py` `_observation()` (`kind == "status200"`) | `predicate = (status == "200")` — probe `probe_rest_root` (`true_when` = "HTTP 200 **and** body JSON 'routes'") became True from the status alone | `predicate = None` always; `predicate_reason` states the body `'routes'` is not in the frozen capture; `rec["limits"] = "…predicate cannot be decided -> Unknown"`. The observation is still **recorded** (`observed: true`, `artifact_line`, `extraction_rule`), but `Context.accepted_predicates` now yields `Unknown` ("verified probe carries no decidable predicate value") → the G7 value is honest rather than invented |
| 2 | `methods.py` `fusion()` tier 2 | `versioncmp.match_ranges(version, nvd["ranges"])` / `(…, cpe["ranges"])` were called unconditionally; an **empty** range list (product filter removed every entry) returns `False` → `B=False` → **Not Applicable** | An empty list is now guarded: `nvd_ranges = nvd["ranges"] or []`, and matching runs only `if nvd_ranges` / `if cpe_ranges`, else verdict `None` with the reason "no \<src\> range scoped to the case product (missing data is not 'outside the range')". Advisory branch already guarded (`if adv_ranges:`) — untouched. Result: empty range → `B = Unknown`, never a fabricated negative |
| 3 | `methods.py` `fusion()` tier 3 (E4) | `patch_linkage` was applied **inside** `if B is True:`, i.e. only after the version had already been placed in the range — E4 could not establish `B=False` when the version was hidden or a range was missing | The E4 check now runs **first**, before tier 1/2: `link = ctx.patch_linkage(case)`; if `link["linked"]` → `B = False` (+ reason `tier 3 (E4): …`) and tier 1/2 is skipped; otherwise the reason `tier 3 (E4): no accepted target<->patched-build linkage` is recorded and the existing tier-1/2 product/version/range logic runs unchanged (the old inner `if B is True:` override was removed). `advisory_only` was already E4-first and is unchanged |
| 4a | `build_inputs.py` advisory `CVE-2023-28121` | one span `[{"start_including": "4.8.0", "end_excluding": "5.6.2"}]` — which marks the patched mid-branch releases (e.g. 5.5.2) as vulnerable | the per-branch union derived from the advisory's own patched-version list + the "4.8.0 and higher" lower bound: `4.8.0–4.8.2, 4.9.0–4.9.1, 5.0.0–5.0.4, 5.1.0–5.1.3, 5.2.0–5.2.2, 5.3.0–5.3.1, 5.4.0–5.4.1, 5.5.0–5.5.2, 5.6.0–5.6.2` (9 branches, each `[branch_first, patch)`). The patched-list quote is kept for provenance (`… Versions 4.8.2 4.9.1 … 6.4.0`, verified verbatim at build time); `scope_note` updated |
| 4b | `build_inputs.py` advisory `CVE-2023-2745` | `[{"line": "6.2", "end_excluding": "6.2.1"}, {"op": "lt", "version": "4.1.38", …}]` — the `4.1.38` threshold is **not in the advisory** (it comes from CPE/NVD) | only `[{"line": "6.2", "end_excluding": "6.2.1"}]`; the quote "All versions since WordPress 4.1 have also been updated." is kept for provenance and the `scope_note` now states that the advisory gives no per-line fixed versions, so only the 6.2 line is precisely encodable and the other lines stay Unknown — **no CPE/NVD threshold is borrowed** |
| 5 | `harness.py` `mode_check()` | called `evaluate()` → `metrics.evaluate()` on the 64 real cases (twice, incl. the label swap): confusion / precision / recall / F1 computed in memory while the docstring said no accuracy number is computed | now `build_context` + `predict_all` only (predictions + records), label-swap comparison on `predict_all` output. Report gains `metrics_computed: false`, `metric_code_invoked: false`, `predictions_computed: true` (plus the existing `benchmark_result_written: false`). A docstring history note records that earlier versions did compute metrics in memory. Docstring history is otherwise untouched |

Also (supporting change, no rule change): `build_inputs.py` now records the sha256 of
the files it writes in `data/build-report.md` (hashed **after** writing, so the digests
are real), plus the previous build's digests for traceability.

## 2. Regenerated derived inputs (new sha256)

`python3 build_inputs.py` (run once, final). `--check` passes (all advisory quotes
verified verbatim against the frozen snapshot bytes; the 30-block mapping parses and
matches D-030).

| artifact | sha256 (2026-10-15) | sha256 (2026-10-14 delivery) |
|---|---|---|
| `experiments/methods/data/observations.json` | `ad747eac0b200787b93d7241d751b56728c49a2a59a711b52fb3a8183d707608` | `df0f6445ad483a1a9762ec1109358aaa7a3920c7a551c8561a6c0e47080f9b19` |
| `experiments/methods/data/advisory_ranges.json` | `c5b706a9c972c435aadf17689e9f5944a9f685305dc2fd14ca2e0a87fab3cbaa` | `18d9af1276b630ca3231005779b6b11e489c9506c78479fb2bf34caa7470478d` |
| `experiments/methods/data/cases.json` | `3ac341b47ea6f0dd133a378733dfb7e302ade09f27abb40df8dfd6568a523817` | `8f05ce70973f7a298ff6481bcb5dbb5ca20a255fb5406881f605a9b78a416ba7` |

`cases.json` — **semantically identical** to the 2026-10-14 build (compared with
`generated_at_utc` stripped: equal); only the embedded regeneration timestamp differs.
No case, label, `label_source` or count changed (`n_unique_cves` 30, `n_cases` 64,
labels 28 Applicable / 34 Not Applicable / 2 Unresolved).

Content deltas in the other two files (checked with `generated_at_utc` stripped):
`observations.json` — exactly the 2 `probe_rest_root` records (CVE-2017-1001000
`wp471`/`wp472`): `predicate_value true → null` + new reason/limits text;
`advisory_ranges.json` — exactly `CVE-2023-2745` (range list + scope_note) and
`CVE-2023-28121` (range list + quotes/extraction/scope_note). Nothing else moved.

## 3. Fixture (pre-step-4 gate)

`python3 fixture/run_fixture.py` → **143/143 pass** (was 112/112; +31 checks).

New synthetic cases / ids:

* `CVE-9000-0010__f_empty_ranges` (new CVE block) — CPE **and** NVD range lists empty
  after the product filter, advisory range null → `cpe_only`/`nvd_only`/
  `http_version_only`/`advisory_only`/`fusion` all **Unknown** (regression for finding 2).
* `CVE-9000-0011__f_e4_linked` / `CVE-9000-0011__f_e4_unlinked` (new CVE block, one
  mapping, two cases differing **only** in whether the verified patch-linkage
  observation is present) — linked → `fusion` **Not Applicable** with `B=False`;
  unlinked → **Unknown** (regression for finding 3; proves E4, not the empty-range
  guard, produced the NA).
* `CVE-9000-0012__f_branch_vuln` (5.5.1) / `CVE-9000-0012__f_branch_patched` (5.5.2,
  new CVE block, per-branch union in the fixture advisory data) — in-branch →
  Applicable, patched mid-branch release → **Not Applicable** (regression for finding 4a).
* Unit checks: `status200 extractor: status-only capture -> predicate Unknown
  (finding 1)` and `…: 404 is also Unknown` (call the real
  `build_inputs._observation`), `an empty range list reports False (the reason for the
  fusion guard)`, `a single span would have mis-classified 5.5.2`.
* Real-input regression checks: the 2 regenerated `status200` observations are recorded
  but undecided; `CVE-2023-28121` is a 9-branch union with 5.5.1 in / 5.5.2 out and
  5.6.1 in / 5.6.2 out and 4.8.1 in / 4.8.2 out; `CVE-2023-2745` keeps only the 6.2 line
  and no `4.1.38` bound.
* `harness.mode_check: no benchmark result written and no metric computed (finding 5)`
  — runs `mode_check` into a temp dir and asserts `metrics_computed`/`metric_code_invoked`
  are `false`, `benchmark_result_written` is `false`, and no `metrics.json` /
  `predictions.json` is produced.

Mutation check (each fix reverted in a scratch copy, the fixture re-run):

| reverted finding | fixture result |
|---|---|
| 1 (status200 → True/False) | 141/143 — 2 failures (both extractor checks) |
| 2 (empty range → False) | 141/143 — 2 failures (`CVE-9000-0010__f_empty_ranges/fusion` + the B-Unknown assertion) |
| 3 (E4 inside `if B is True`) | 139/143 — 4 failures (incl. the E4 pair A + the pre-existing `CVE-9000-0006` check) |
| 4a (`CVE-9000-0012` fixture data collapsed to one span) | 140/143 — 3 failures |
| 4a (real `advisory_ranges.json` collapsed to one span) | 140/143 — 3 failures |
| 5 (`mode_check` → `evaluate`) | 142/143 — 1 failure |

## 4. `harness.py check` (structural gate, no result emitted)

`python3 harness.py check` → rc 0. Report (`output/check/check-report.json`):
`n_cases` 64, `n_methods` 5, `n_records` 320, all predictions in the allowed set,
label isolation preserved, no record missing reasons/provenance,
**`benchmark_result_written: false`**, **`metrics_computed: false`**,
**`metric_code_invoked: false`**, `predictions_computed: true`.

`python3 harness.py load` → mapping sha256 `f266673ee…` verified, snapshot manifest
verified, 30 CVE / 64 case counts unchanged. The step-4 benchmark was **not** run.

## 5. Frozen artifacts — untouched

* `notes/collector-mapping-30cve.md` — sha256 still
  `f266673ee3f1b2d6ae14b0ac2357a550d63a4013b4eb7f1e8676509248d7fbd1` (D-030), file
  mtime unchanged (2026-10-14).
* `data/public-snapshot/` — unchanged (manifest mtime 2026-10-11);
  `verify_snapshot.py --dir data/public-snapshot` → 92 artifacts checked, 0 hash
  mismatches, OK.
* No registry / selection-log / spec / decision / ground-truth-label file was edited.
  The D-032 proposal (downgrade `CVE-2017-1001000.probe_rest_root` `verified→pending`)
  was **not** applied — it is a mapping edit and awaits the researcher's decision; the
  runtime outcome is already `Unknown` via the finding-1 fix + the G7 gate.

## 6. Prediction-level effect (verification only — no metric, no benchmark)

Both states were run through `harness.build_context` + `harness.predict_all` in scratch
directories (`/tmp/opencode/…`, nothing written into the repo) — old code + old inputs
vs. new code + new inputs, 64 cases × 5 methods:

| case | method | before | after |
|---|---|---|---|
| `CVE-2017-1001000__vuln` | `fusion` | Applicable | **Unknown** |

Exactly **one** prediction changes — the review's prediction for finding 1 (the
`p_rest_reachable=True` that was fabricated from a status-only capture made
`P_i=True`, so fusion concluded Applicable). Findings 2/3/4 produce **no** prediction
change on the current benchmark data: they are latent-bug fixes, consistent with the
review's "tiềm ẩn" classification (every real case has a scoped range, no `verified`
patch-linkage probe, and no observed mid-branch-but-patched version for 28121/2745).

## 7. Open item flagged to the researcher (not silently changed)

The corrected `CVE-2023-2745` encoding keeps only the line-scoped 6.2 range. Because
the range model has no "undecidable remainder branch", a **non-6.2** observed version
(e.g. 4.1.37) is now mechanically **False** ("outside advisory line 6.2") rather than
`None`/Unknown, whereas the `scope_note` says the older lines remain Unknown. No
benchmark case observes a non-6.2 version for this CVE, so there is no measured effect
(the two cases are 6.2.0 Applicable / 6.2.1 Not Applicable, unchanged). If the
researcher wants "other lines → Unknown" to be mechanical rather than note-level, the
encoding needs a decision — it is not something this fix round should decide.

## 8. How to reproduce this state

```bash
cd experiments/methods
python3 build_inputs.py                 # writes the 3 derived inputs + build-report.md
python3 fixture/run_fixture.py          # 143/143
python3 harness.py check                # rc 0; metrics_computed: false
# step 4 (NOT run here): python3 harness.py benchmark --run-benchmark
```
