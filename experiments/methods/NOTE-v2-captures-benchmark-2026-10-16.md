# NOTE — V2 round: D-033/D-034 synced, V2 captures wired, V2 benchmark run once (2026-10-16)

> Engineer (Flash). Task (parent = researcher): sync the new mapping hash, wire the four
> V2-verified probes into the observation extraction, fix the CVE-2024-10924 collector
> (two predicates from one response), regenerate the derived inputs and run the **V2**
> benchmark **once** into a separate directory. Raw artifacts only; interpretation is the
> researcher's (`reviews/`, `CURRENT_STATE.md`).
>
> **No frozen artifact was edited**: `notes/collector-mapping-30cve.md`,
> `data/public-snapshot/`, `experiments/26cve/` (registry / selection-log / case READMEs),
> the ground-truth labels, `data/cases.json` labels and `output/benchmark/` (V1) are
> untouched. Only `experiments/methods/*.py`, `fixture/`, the derived `data/*.json` and
> two docs were written.

## 0. Inputs / decisions applied

| item | value |
|---|---|
| mapping amendment | **D-034** (4 probes `pending` → `verified`) on top of **D-033** (two probe request paths) and D-032 |
| mapping sha256 | `9a43a0f2b79004e3049aeb3bc9c51e7ec769365639df4687c8c19128bc25ca23` (30 YAML blocks, parse OK, 21 `verified` / 31 `pending` / 4 `needs_control`) |
| V2 captures | `experiments/methods/captures-v2/**` (raw; unmodified) |
| rulings read | `reviews/Review_v2_captures_phanquyet_2026-10-15.md`, `captures-v2/README-2026-10-15.md`, `captures-v2/CVE-2023-3460/README-2026-10-16-fixture-fix.md` |

`MAPPING_SHA256` synced to the above in **both** `build_inputs.py` (line 42) and
`harness.py` (line 58 + module docstring); `README.md` (line 66) updated too. Grep for the
older hashes (`a97de36a…`, `f266673e…`, `130d12895…`, `14f04fc12…`) finds **no live code or
loader** — the remaining occurrences are historical/dated records only:
`context/DECISIONS.md` (the D-030 → D-032 → D-033 → D-034 chain), `context/CURRENT_STATE.md`
§48, `context/TODO.md`, `notes/collector-mapping-30cve.md`'s amendment header (D-030 hash,
kept "để đối chiếu"), the earlier `experiments/methods/NOTE-*.md` / `REPORT-step3.md` /
spec / review docs, and the V1 `output/benchmark/run-metadata.json`.
**The brief's `a97de36a…` does not occur anywhere in the workspace** (it is not a hash this
repo has ever used).

> Documentation gap flagged (not fixed — the mapping is frozen): the mapping file's header
> amendment log lists D-032 and D-033 but **not D-034**, although D-034 is what changed the
> file's hash to `9a43a0f2…` and the four probe blocks carry "D-034 verified" notes.

## 1. Extraction changes (`build_inputs.py`)

Four new/updated extractor specs, all reading `experiments/methods/captures-v2/` (new
`ARTIFACTS` keys `v2_*`), plus three new value kinds.

| probe | artifact(s) | kind | rule |
|---|---|---|---|
| `CVE-2017-1001000.probe_rest_root` (`p_rest_reachable`) | `8711-…-GET-rest-route-index-SUPPLEMENTARY.txt`, `8712-…` | `rest_routes` | 200 **and** body contains `"routes"` → True; 200 without `routes` → False; other status → Unknown |
| `CVE-2024-10924.probe_two_fa_route` (`p_2fa_enabled` **+** `p_skip_onboarding_route`) | `8081-2fa-on-…`, `8081-2fa-off-…`, `8082-fixed-9.1.2-2fa-on-…` | `rest_route_presence` | 400 + `rest_missing_callback_param` → True; 404 + `rest_no_route` → False; else Unknown |
| `CVE-2023-3460.observe_plugin_readme_version` (`p_version_observed`) | `8830-um266-GET-readme.txt`, `8831-um267-GET-readme.txt` | `version` | `Stable tag:` token → E5 (2.6.6 / 2.6.7) |
| `CVE-2023-3460.probe_um_register_form` (`p_open_registration_form`) | `8830-um266-GET-register-page.txt`, `8831-um267-GET-page_id6-AS-SPECIFIED.txt` | `form_markers` | 200 **and** `um-form` + `user_login-7` + `_wpnonce` → True; 200 with incomplete markers → False; other status → Unknown |

* The `/wp-json/` captures (`8711-…-GET-wp-json.txt`, `8712-…`) are the 200-`text/html`
  trap and are **not** referenced (checked in the fixture: the accepted 1001000 route
  observation's `artifact_ref` must end with `GET-rest-route-index-SUPPLEMENTARY.txt`).
* `_extract()` now also returns the captured body so the combined
  status+body `true_when`/`false_when` can be evaluated; the old `status200` kind and its
  fixture checks are kept unchanged (a status-only capture still yields `Unknown`).

### 1a. CVE-2024-10924 collector fix — two predicates from one response (R4)

`probe_two_fa_route` declares `also_maps_to: ["p_skip_onboarding_route"]`. When a verified
probe produces an accepted observation, `build_observations()` now additionally emits one
record per extra condition, built by `_shared_extraction()`: same artifact ref / line /
status / predicate value, only `condition_id` (+ its `kind`) and the reason change
(`shared_response_with` records the originating probe). No second probe and no second
request exist. Result on the real data (verified in the fixture and by mutation):

| case | response | `p_2fa_enabled` | `p_skip_onboarding_route` | shared record |
|---|---|---|---|---|
| `CVE-2024-10924__9_1_1_1_2fa_on` | 400 `rest_missing_callback_param` | True | True | 1 |
| `CVE-2024-10924__9_1_1_1_2fa_off` | 404 `rest_no_route` | False | False | 1 |
| `CVE-2024-10924__9_1_2_2fa_on_fixed` | 400 (fixed build, 2FA on) | True | True | 1 |

## 2. Derived inputs regenerated (`python3 build_inputs.py`, once)

| artifact | sha256 (V2) | sha256 (previous, V1) |
|---|---|---|
| `experiments/methods/data/cases.json` | `98dd5f6a1aa0709c952cf298a10c574da5eada7452dac01d4f33ca1e64829c1f` | `f9790f7b63dd3bb376fa4b9f4456b45a5b9c2675b3d31eba75f6120b9633feee` |
| `experiments/methods/data/observations.json` | `ba72d8071ddaa4a1fe990647793295f328e8de541bd66907108d65d9cad1a0a8` | `98a9b0ab52c85937cbd595b1e09bfe5b7ad1b69623eb8c5fba47247c3fa5241e` |
| `experiments/methods/data/advisory_ranges.json` | `32a51c8a8e4a2f0f22b6351f62f3554650a871e238c151de1464bbf3904c9f22` | `c55de8be4255055050f04a10ce4c460b9040921a90a521cad1693229ac4917df` |

* **`cases.json` — semantically unchanged (verified mechanically, not asserted).**
  Replacing only (i) the embedded `generated_at_utc` with the previous build's timestamp
  `2026-10-15T00:06:40Z` and (ii) the `sources.mapping` block (sha256 + decision note)
  with its D-032 value reproduces the previous file's sha256 `f9790f7b…` **byte-exactly**.
  Case ids, labels, `label_branch`, `scenario_tags`, counts (30 CVE ids / 64 cases /
  Applicable 28 · Not Applicable 34 (a 28, b 6) · Unresolved 2) are identical.
* **`advisory_ranges.json` — content unchanged (verified mechanically).** Replacing only
  the `generated_at_utc` value with `2026-10-15T00:06:40Z` reproduces the previous sha256
  `c55de8be…` **byte-exactly** ⇒ the whole `cves` payload is identical; only the embedded
  timestamp moved. (The advisory-extraction code was not touched in this round.)
* **`observations.json` — the real change.** Counts:

  | counter | V1 | V2 |
  |---|---|---|
  | `verified_probe_requests` (1 per HTTP request) | 37 | **46** |
  | `accepted_observations` (records) | 37 | **49** |
  | `extra_condition_extractions` (shared response, R4) | 0 | **3** |
  | `unobserved_entries` (G7) | 86 | **77** |
  | cases with ≥1 accepted observation | 30 | **32** |

  The key `verified_probes_used` was renamed to the two explicit counters above
  (`verified_probe_requests` / `accepted_observations`) because one request can now
  produce two records; `_shared_extraction` and the policy string document the rule.

## 3. Gates

* `python3 build_inputs.py --check` → OK (all advisory quotes re-verified against the
  frozen bytes; the four new extractor patterns all matched — a miss aborts the build).
* `python3 fixture/run_fixture.py` → **174/174 pass, 0 fail** (was 161/161; new block
  `h2` = the V2 real-data assertions + extractor unit checks for `rest_routes`,
  `rest_route_presence`, `form_markers` and `_shared_extraction`).
  **Mutation check** (scratch, not saved): dropping `also_maps_to` → the 10924 record set
  collapses to `['p_2fa_enabled']` and the counts change (checks fail); pointing the 3460
  fixed state at the STALE `8831-um267-GET-register-page.txt` → `predicate_value = False`
  (`user_login-7` absent; checks fail); pointing the 1001000 route probe at the
  `/wp-json/` files → `predicate_value = False` (checks fail).
* `python3 harness.py load` → rc 0, mapping `9a43a0f2…` == expected, snapshot verifier
  `92 artifacts / 0 mismatches`, counts 30/64/28-34-2.
* `python3 harness.py check` → rc 0; `all_predictions_in_allowed_set: true`,
  `label_isolation_preserved: true`, `benchmark_result_written: false`,
  `metrics_computed: false`, `metric_code_invoked: false`. (Writes only
  `output/check/check-report.json`.)

## 4. V2 benchmark — run **once** (no tuning after the run)

```
python3 harness.py benchmark --run-benchmark --out experiments/methods/output/benchmark-v2
```

Unit = case; N = 62 = 64 cases − 2 Unresolved (`CVE-2019-6341`, `CVE-2023-5631`,
reported separately in `excluded_unresolved`).

| method | N | TP | FP | TN | FN_def | U_A | U_N | precision | recall | F1 | coverage | Unknown rate |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `cpe_only` | 62 | 10 | 3 | 9 | 0 | 18 | 22 | 0.7692 | 0.3571 | 0.4878 | 0.3548 | 0.6452 |
| `nvd_only` | 62 | 10 | 3 | 9 | 0 | 18 | 22 | 0.7692 | 0.3571 | 0.4878 | 0.3548 | 0.6452 |
| `advisory_only` | 62 | 0 | 0 | 8 | 0 | 28 | 26 | N/A | 0.0 | 0.0 | 0.1290 | 0.8710 |
| `http_version_only` | 62 | 10 | 3 | 9 | 0 | 18 | 22 | 0.7692 | 0.3571 | 0.4878 | 0.3548 | 0.6452 |
| `fusion` | 62 | 3 | 0 | 11 | 0 | 25 | 23 | 1.0 | 0.1071 | 0.1935 | 0.2258 | 0.7742 |

Unrounded: `cpe_only`/`nvd_only`/`http_version_only` precision `0.7692307692307693`,
recall `0.35714285714285715`, F1 `0.4878048780487805`, coverage
`0.3548387096774194`, unknown rate `0.6451612903225806`; `fusion` precision `1.0`,
recall `0.10714285714285714`, F1 `0.1935483870967742`, coverage
`0.22580645161290322`, unknown rate `0.7741935483870968`; `advisory_only` recall/F1
`0.0`, coverage `0.12903225806451613`, unknown rate `0.8709677419354839`.

`duplicate_prediction_vectors` = `[["cpe_only", "http_version_only", "nvd_only"]]`
(identical 64-case vectors — unchanged from V1).

Fusion's determined cells: **TP** = `CVE-2017-1001000__vuln`, `CVE-2023-3460__vuln`,
`CVE-2024-10924__9_1_1_1_2fa_on`; **TN** = 11 (10 branch-a single-build negatives +
`CVE-2024-10924__9_1_1_1_2fa_off`); **FP/FN_def = 0**.

Outputs (new directory; V1 untouched):
`output/benchmark-v2/metrics.json` `d483d3ce…`, `predictions.json` `7c26d226…`,
`run-metadata.json` `bfe90c60…` — the run metadata records mapping `9a43a0f2…` and the
three derived-input hashes of §2.

### 4a. V1 `output/benchmark/` untouched (verified)

| file | sha256 (before and after the V2 run) | mtime |
|---|---|---|
| `output/benchmark/metrics.json` | `d80405a0ce791129a4cb184417ab222b27d5cee3f328cb3e8799c8a538717f68` | 2026-10-15 07:09:29 |
| `output/benchmark/predictions.json` | `a90573459939ca2b1b1ed7cfdd474a72ee0f1d6d2374570d24596b8942e2694e` | 2026-10-15 07:09:29 |
| `output/benchmark/run-metadata.json` | `baf396e810b7faabf55a07d470bc4e87a04b05a3676624063a9f0343a3203b29` | 2026-10-15 07:09:29 |

(Only `output/run-metadata.json` — the `harness.py load` evidence file, *not* a benchmark
result — and `output/check/check-report.json` were refreshed by the gates in §3.)

## 5. V1 → V2 prediction delta (exact, from the two `predictions.json` files)

| case | GT | method(s) | V1 → V2 |
|---|---|---|---|
| `CVE-2017-1001000__vuln` | Applicable | `fusion` | Unknown → **Applicable** (TP) |
| `CVE-2024-10924__9_1_1_1_2fa_on` | Applicable | `fusion` | Unknown → **Applicable** (TP) |
| `CVE-2024-10924__9_1_1_1_2fa_off` | Not Applicable (b) | `fusion` | Unknown → **Not Applicable** (TN, branch **b**) |
| `CVE-2023-3460__vuln` | Applicable | `cpe_only`, `nvd_only`, `http_version_only`, `fusion` | Unknown → **Applicable** (TP) |
| `CVE-2023-3460__fixed` | Not Applicable (a) | `cpe_only`, `nvd_only`, `http_version_only`, `advisory_only`, `fusion` | Unknown → **Not Applicable** (TN) |

* 5 fusion cells changed (3 Applicable, 2 Not Applicable); 2 cells per level-1 method
  (both CVE-2023-3460 cases, driven by the newly accepted readme Stable-tag E5 version);
  1 cell for `advisory_only` (3460 fixed). No other cell differs anywhere
  (`CVE-2017-1001000__fixed` and `CVE-2024-10924__9_1_2_2fa_on_fixed` were already correct
  negatives after the V1 fixes).
* Aggregate: fusion TP 0→3, FP 0→0, TN 9→11, U_A 28→25, U_N 25→23; level-1 baselines
  TP 9→10, TN 8→9, U_A 19→18, U_N 23→22; `advisory_only` TN 7→8, U_N 27→26.
* **V1 flagged observation (2) is resolved**: the branch-b rule now fires on real data
  (`CVE-2024-10924__9_1_1_1_2fa_off` → `branch b: … every impact path has a precondition
  determined False (B not required)` with `B=True`). V1 flagged observation (1) improves
  but is not eliminated: fusion is no longer zero-positive (precision 1.0), yet its recall
  (0.107) / F1 (0.194) remain below the level-1 baselines (0.357 / 0.488); observation (3)
  (`cpe_only`=`nvd_only`=`http_version_only`, one vector) still holds.

### 5a. Development / scenario groups (secondary; membership changed as a side effect of D-034)

`CVE-2017-1001000` and `CVE-2023-3460` are marked `used_for_signal_development = true` by
D-034, so their 4 cases move from `no_development` into `signal_development`
(9 → 13 cases; `no_development` 41 → 37). V2 by-group confusion (TP/FP/TN/U_A/U_N):
`fusion` rule_development 1/0/3/4/4, signal_development 2/0/5/4/2, no_development 0/0/3/17/17;
level-1 baselines rule 2/2/2/3/3, signal 5/1/4/1/2, no_development 3/0/3/14/17;
`advisory_only` rule 0/0/1/5/6, signal 0/0/4/6/3, no_development 0/0/3/17/17. Tag
`CPE-sai`: fusion V2 = 1/0/1 (the 1001000-vuln TP, i.e. fusion now resolves the wrong-CPE
case instead of abstaining); tags `ẩn-version`, `config-tắt`, `backport` unchanged.

## 6. Flags for the researcher (recorded, not fixed)

1. **Mapping `artifact_refs` naming vs the frozen evidence (3460).**
   `probe_um_register_form.validation.artifact_refs` lists
   `8831-um267-GET-register-page.txt`, but the lab marked that file **STALE** on
   2026-10-16 (it is the pre-fix `?page_id=12` capture, form id 6 → `user_login-6`); the
   superseding aligned capture is `8831-um267-GET-page_id6-AS-SPECIFIED.txt`. The mapping's
   own `note` describes the aligned `?page_id=6` capture, so the extractor reads
   `…-page_id6-AS-SPECIFIED.txt`. The mapping is frozen (D-034 hash) and was **not**
   edited; if the researcher wants the `artifact_refs` list to name the superseding file,
   that is a new mapping amendment (new hash → regenerate inputs → re-run).
2. **`CVE-2017-1001000.probe_rest_root.artifact_refs`** point at the two `?rest_route=/`
   SUPPLEMENTARY files — consistent with the extractor; the `/wp-json/` files are unused.
3. **Fixed build 9.1.2 answers 400 on the empty-body route probe** (same status as the
   vulnerable 2FA-on state). Per D-033 that is not a defect: the probe distinguishes 2FA
   on/off only; vulnerability is `B` (version). V2 behaves accordingly
   (`…__9_1_2_2fa_on_fixed`: both predicates True, `B=False` → Not Applicable/a).
4. **`_STATE_ALIAS`** in `build_inputs.py` is unused dead code (pre-existing). Left as is;
   removal would be a cosmetic change.
5. The `a97de36a…` hash named in the task brief does not occur anywhere in the workspace
   (grep); the stale hashes actually present were `f266673e…` (D-030) and `130d12895…`
   (D-032) in live code, and `14f04fc12…` (D-033) in `DECISIONS.md` only.

## 7. Files written / changed in this round

| file | change |
|---|---|
| `experiments/methods/build_inputs.py` | `MAPPING_SHA256`; `ARTIFACTS` `v2_*` keys; 4 extractor specs; `_extract` returns body; new kinds `rest_routes` / `rest_route_presence` / `form_markers`; `also_maps_to` + `_shared_extraction`; counts keys; report/hash text |
| `experiments/methods/harness.py` | `MAPPING_SHA256` + docstring (no logic change) |
| `experiments/methods/README.md` | new hash, V2-round header, fixture count 174, `benchmark/` vs `benchmark-v2/`, shared-response rule |
| `experiments/methods/fixture/run_fixture.py` | docstring `h2` row; new V2 real-data + extractor checks (161 → 174 checks) |
| `experiments/methods/data/{cases,observations,advisory_ranges}.json`, `build-report.md` | regenerated (hashes §2) |
| `experiments/methods/output/benchmark-v2/` | new V2 benchmark run |
| `experiments/methods/output/check/check-report.json`, `output/run-metadata.json` | refreshed by the gates |
| `experiments/methods/NOTE-v2-captures-benchmark-2026-10-16.md` | this note |

No `methods.py` / `metrics.py` / `versioncmp.py` logic was changed in this round.
