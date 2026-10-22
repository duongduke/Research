#!/usr/bin/env python3
"""run_fixture.py — synthetic fixture for step 3 (phase C).

Runs the **same** `methods.py` / `metrics.py` code path as the real benchmark, on a
hand-built synthetic dataset, and asserts the properties the researcher must be able
to rely on before step 4:

| # | property | check |
|---|---|---|
| a | inclusive / exclusive / exact version boundaries | CVE-9000-0001/0002 cases |
| b | product + source filtering (CPE not product-scoped; non-vulnerable entries) | CVE-9000-0002 cases |
| c | B / P_i separation, branch-b NA without B=True, G7 gate, missing data / conflict -> Unknown, E4 patch linkage | CVE-9000-0003/0004/0005/0006/0008 |
| c2 | 2026-10-15 review regressions: empty range list -> Unknown (not NA); E4 independence pair; advisory per-branch union | CVE-9000-0010/0011/0012 + `versioncmp` unit checks |
| c3 | D-032 / partial-scope advisory: an out-of-line version is Unknown for advisory-only (never "Not Applicable"), the in-line/patched releases still decide, and fusion resolves the out-of-line case from NVD/CPE instead of inheriting the advisory's Unknown | CVE-9000-0013 cases + `versioncmp` unit checks |
| d | label isolation (methods never see the label) | swapped-label rerun + runtime assertion in `methods.py` |
| e | metrics with U_A and a zero denominator | `metric_fixture` block |
| f | hash mismatch (tampered mapping / tampered snapshot) -> hard failure | `harness.load_mapping` / `harness.verify_snapshot` |
| g | version parsing / range boundaries / scope mismatch | `versioncmp` unit list |
| h | the regenerated real inputs and check-mode behaviour: status200 extractor -> Unknown; real advisory unions; `mode_check` writes no benchmark result and computes no metric | `build_inputs._observation`, `data/observations.json`, `data/advisory_ranges.json`, `harness.mode_check` |
| h2 | **V2 (D-033/D-034)**: the four V2-validated probes are accepted observations from `captures-v2/` — REST root 200 + JSON `routes` (and the `/wp-json/` text/html trap is not used), the 10924 single response emits **both** `p_2fa_enabled` and `p_skip_onboarding_route` (R4), 3460 readme Stable tag -> E5 and the aligned registration-form markers; plus extractor unit checks for the three new kinds | `data/observations.json`, `build_inputs._observation`, `build_inputs._shared_extraction`, frozen mapping requests |

Usage:  python3 run_fixture.py [out_dir]
Exit code 0 only if every check passes.

Fix round 2026-10-15 (review `reviews/Review_buoc3_implementation_2026-10-15.md`):
sections `c2`/`h` above were added so the five implementation findings cannot
silently return.  Each new check was verified to fail when its fix is reverted
(mutation check: reverting finding 1 fails 2 checks, finding 2 fails 2, finding 3
fails 4, finding 4a/4b fail 3 each, finding 5 fails 1).  This fixture is synthetic:
nothing here is a measurement or a claim about method performance.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
METHODS = HERE.parent
REPO = METHODS.parent.parent
sys.path.insert(0, str(METHODS))
sys.path.insert(0, str(HERE))

import harness  # noqa: E402
import metrics as metrics_mod  # noqa: E402

FIXTURE_DIR = HERE
OUT_DEFAULT = HERE / "output"


def load_json(p: Path) -> dict:
    return json.loads(Path(p).read_text(encoding="utf-8"))


class Checks:
    def __init__(self):
        self.results = []

    def check(self, name: str, ok: bool, detail: str = ""):
        self.results.append({"check": name, "pass": bool(ok), "detail": detail})
        return ok

    def summary(self) -> dict:
        return {
            "n_checks": len(self.results),
            "n_pass": sum(1 for r in self.results if r["pass"]),
            "n_fail": sum(1 for r in self.results if not r["pass"]),
        }


def main(out_dir: Path = OUT_DEFAULT) -> int:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    checks = Checks()

    mapping_doc = (FIXTURE_DIR / "fixture_mapping.md").read_text(encoding="utf-8")
    mapping = harness.parse_mapping_text(mapping_doc, expected_blocks=None)
    snapshot = load_json(FIXTURE_DIR / "fixture_snapshot.json")
    snapshot = {k: v for k, v in snapshot.items() if not k.startswith("_")}
    advisory = load_json(FIXTURE_DIR / "fixture_advisory_ranges.json")["cves"]
    observations = load_json(FIXTURE_DIR / "fixture_observations.json")["cases"]
    cases_doc = load_json(FIXTURE_DIR / "fixture_cases.json")
    cases = cases_doc["cases"]

    # --- run all five methods on every fixture case (same code path as step 4) -- #
    result = harness.evaluate(mapping, snapshot, advisory, observations, cases)
    per_method, records = result["per_method"], result["records"]

    for exp in cases_doc["expectations"]:
        got = per_method[exp["method"]].get(exp["case_id"])
        checks.check(
            f"expectation {exp['case_id']} / {exp['method']}",
            got == exp["expect"],
            f"expected {exp['expect']}, got {got} ({exp['why']})",
        )

    # --- (c) extra structural assertions --------------------------------------- #
    rec = {(r["case_id"], r["method"]): r for r in records}
    nb = rec[("CVE-9000-0003__f_blocked_noversion", "fusion")]
    checks.check(
        "branch b without B=True",
        nb["prediction"] == "Not Applicable" and nb["evidence"]["B"] == "Unknown"
        and all(p["P_i"] == "False" for p in nb["evidence"]["P_i"]),
        f"B={nb['evidence']['B']}, P_i={[p['P_i'] for p in nb['evidence']['P_i']]}, pred={nb['prediction']}",
    )
    pg = rec[("CVE-9000-0008__f_pending_bogus", "fusion")]
    checks.check(
        "G7 gate: pending probe yields Unknown",
        pg["prediction"] == "Unknown" and any("G7 gate" in r for r in pg["reasons"]),
        f"pred={pg['prediction']}",
    )
    nc = rec[("CVE-9000-0003__f_needs_control_bogus", "fusion")]
    checks.check(
        "G7 gate: needs_control probe yields Unknown (bogus value ignored)",
        nc["prediction"] == "Unknown" and any("G7 gate" in r for r in nc["reasons"]),
        f"pred={nc['prediction']}",
    )
    prec = rec[("CVE-9000-0004__f_precedence", "fusion")]
    checks.check(
        "precedence resolves source disagreement (advisory wins, reported)",
        prec["prediction"] == "Not Applicable"
        and prec["evidence"]["tier2_source_verdicts"]["disagreement"] is True
        and prec["evidence"]["tier2_source_verdicts"]["chosen"] == "advisory",
        f"verdicts={prec['evidence']['tier2_source_verdicts']}",
    )
    tc = rec[("CVE-9000-0005__f_tier_conflict", "fusion")]
    checks.check(
        "same-tier conflict -> Unknown",
        tc["prediction"] == "Unknown" and "same-tier conflict" in json.dumps(tc["evidence"]),
        f"pred={tc['prediction']}",
    )
    pl = rec[("CVE-9000-0006__f_no_range", "fusion")]
    checks.check(
        "E4 patch linkage sets B=False without a readable range",
        pl["prediction"] == "Not Applicable" and pl["evidence"]["B"] is False,
        f"B={pl['evidence']['B']}, pred={pl['prediction']}",
    )
    empty = rec[("CVE-9000-0007__f_empty_path", "fusion")]
    checks.check(
        "empty impact path = True (vacuously), no precondition invented",
        empty["prediction"] == "Applicable" and empty["evidence"]["P_i"][0]["P_i"] == "True",
        f"pred={empty['prediction']}",
    )
    # --- (c2) 2026-10-15 review regressions (findings 2/3/4a) ------------------ #
    er = rec[("CVE-9000-0010__f_empty_ranges", "fusion")]
    checks.check(
        "fusion: empty CPE+NVD range list -> B Unknown, not Not Applicable",
        er["prediction"] == "Unknown"
        and er["evidence"]["B"] == "Unknown"
        and er["evidence"]["tier2_source_verdicts"]["nvd"] is None
        and er["evidence"]["tier2_source_verdicts"]["cpe"] is None
        and er["evidence"]["tier2_source_verdicts"]["chosen"] is None,
        f"B={er['evidence']['B']}, pred={er['prediction']}, verdicts={er['evidence'].get('tier2_source_verdicts')}",
    )
    linked = rec[("CVE-9000-0011__f_e4_linked", "fusion")]
    unlinked = rec[("CVE-9000-0011__f_e4_unlinked", "fusion")]
    checks.check(
        "E4 pair (A): verified patch linkage -> B=False / Not Applicable with no version and no range",
        linked["prediction"] == "Not Applicable"
        and linked["evidence"]["B"] is False
        and linked["evidence"]["tier3_patch"]["linked"] is True
        and linked["evidence"]["tier1_identity"]["version"] is None
        and any("tier 3 (E4)" in r for r in linked["evidence"]["tier2_range"]["reasons"]),
        f"B={linked['evidence']['B']}, pred={linked['prediction']}, tier3={linked['evidence']['tier3_patch']}",
    )
    checks.check(
        "E4 pair (B): identical input without the linkage -> Unknown (E4, not the empty range, drove (A))",
        unlinked["prediction"] == "Unknown"
        and unlinked["evidence"]["B"] == "Unknown"
        and unlinked["evidence"]["tier3_patch"]["linked"] is False
        and unlinked["evidence"]["tier1_identity"]["identified"] is True
        and unlinked["evidence"]["tier1_identity"]["version"] is None,
        f"B={unlinked['evidence']['B']}, pred={unlinked['prediction']}, tier3={unlinked['evidence']['tier3_patch']}",
    )
    br_v = rec[("CVE-9000-0012__f_branch_vuln", "fusion")]
    br_p = rec[("CVE-9000-0012__f_branch_patched", "fusion")]
    checks.check(
        "advisory per-branch union: mid-branch patched release (5.5.2) is out of range, 5.5.1 is in range",
        br_v["prediction"] == "Applicable" and br_p["prediction"] == "Not Applicable"
        and br_p["evidence"]["tier2_source_verdicts"]["advisory"] is False,
        f"5.5.1 -> {br_v['prediction']}, 5.5.2 -> {br_p['prediction']}",
    )
    # --- (c3) partial-scope advisory line (CVE-2023-2745 encoding) -------------- #
    ool = rec[("CVE-9000-0013__f_out_of_line", "advisory_only")]
    ool_f = rec[("CVE-9000-0013__f_out_of_line", "fusion")]
    checks.check(
        "partial-scope advisory: an out-of-line version is Unknown for advisory-only, never 'Not Applicable'",
        ool["prediction"] == "Unknown"
        and ool["prediction"] != "Not Applicable"
        and any("outside the advisory-defined line 6.2" in r for r in ool["reasons"]),
        f"pred={ool['prediction']!r}, reasons={ool['reasons']}",
    )
    checks.check(
        "partial-scope advisory: fusion does not inherit the advisory Unknown — NVD/CPE still decide",
        ool_f["prediction"] == "Applicable"
        and ool_f["evidence"]["tier2_source_verdicts"]["advisory"] is None
        and ool_f["evidence"]["tier2_source_verdicts"]["chosen"] == "nvd_configurations"
        and ool_f["evidence"]["B"] is True,
        f"pred={ool_f['prediction']}, verdicts={ool_f['evidence'].get('tier2_source_verdicts')}",
    )
    inl = rec[("CVE-9000-0013__f_in_line", "advisory_only")]
    lp = rec[("CVE-9000-0013__f_line_patched", "advisory_only")]
    checks.check(
        "partial-scope advisory: the determined 6.2 line still decides in-range and patched releases",
        inl["prediction"] == "Applicable" and lp["prediction"] == "Not Applicable",
        f"6.2.0 -> {inl['prediction']}, 6.2.1 -> {lp['prediction']}",
    )
    import versioncmp as _vc

    checks.check(
        "advisory per-branch union: a single span would have mis-classified 5.5.2",
        _vc.match_ranges("5.5.2", [{"start_including": "4.8.0", "end_excluding": "5.6.2"}])[0] is True
        and _vc.match_ranges("5.5.2", [{"start_including": "4.8.0", "end_excluding": "4.8.2"},
                                       {"start_including": "4.9.0", "end_excluding": "4.9.1"},
                                       {"start_including": "5.5.0", "end_excluding": "5.5.2"},
                                       {"start_including": "5.6.0", "end_excluding": "5.6.2"}])[0] is False,
        "single span 4.8.0<=v<5.6.2 matches 5.5.2; the per-branch union does not",
    )
    # missing data is never a negative (cases decided by positive patch evidence
    # or by their own source are excluded — those are not "negative from silence")
    silence_excluded = {
        ("CVE-9000-0006__f_no_range", "advisory_only"),
        ("CVE-9000-0006__f_no_range", "fusion"),
        ("CVE-9000-0005__f_tier_conflict", "cpe_only"),
        ("CVE-9000-0005__f_tier_conflict", "nvd_only"),
    }
    for cid in ("CVE-9000-0001__f_noversion", "CVE-9000-0006__f_no_range", "CVE-9000-0005__f_tier_conflict"):
        for method in ("cpe_only", "nvd_only", "http_version_only", "advisory_only", "fusion"):
            if (cid, method) in silence_excluded:
                continue
            r = rec[(cid, method)]
            checks.check(
                f"missing/undecidable data is not a negative ({cid}/{method})",
                r["prediction"] != "Not Applicable",
                f"pred={r['prediction']}",
            )

    # --- (d) label isolation --------------------------------------------------- #
    swapped = []
    for case in cases:
        c = dict(case)
        c["ground_truth_label"] = "Applicable" if c["ground_truth_label"] == "Not Applicable" else "Not Applicable"
        swapped.append(c)
    result2 = harness.evaluate(mapping, snapshot, advisory, observations, swapped)
    checks.check(
        "label isolation: predictions are invariant under label swap",
        result2["per_method"] == per_method,
        "prediction vectors differ when labels change",
    )
    leaked = 0
    try:
        from methods import _assert_label_free

        _assert_label_free({"case_id": "x", "ground_truth_label": "Applicable"})
    except AssertionError:
        leaked = 1
    checks.check("label isolation: runtime guard rejects a labelled case view", leaked == 1, "")

    # --- (e) metrics ----------------------------------------------------------- #
    mf = cases_doc["metric_fixture"]
    mcases = mf["cases"]
    per_method_preds = mf["predictions"]
    metrics_block = metrics_mod.evaluate(per_method_preds, mcases)
    for name, exp in mf["expected"].items():
        got_conf = metrics_block["methods"][name]["confusion"]
        got_scores = metrics_block["methods"][name]["scores"]
        checks.check(f"metrics confusion [{name}]", got_conf == exp["confusion"], f"got {got_conf}")
        for key, val in exp["scores"].items():
            got = got_scores[key]
            ok = (got == val) if isinstance(val, str) else abs(got - val) < 1e-9
            checks.check(f"metrics score {name}.{key}", ok, f"expected {val}, got {got}")
        checks.check(
            f"metrics: Unresolved excluded from N [{name}]",
            got_scores["N"] == 5 and len(metrics_block["methods"][name]["excluded_unresolved"]) == 1,
            f"N={got_scores['N']}, excluded={metrics_block['methods'][name]['excluded_unresolved']}",
        )
    checks.check(
        "metrics: duplicate prediction vectors reported",
        any(sorted(d) == ["all_unknown", "all_unknown_copy"] for d in metrics_block["duplicate_prediction_vectors"]),
        f"{metrics_block['duplicate_prediction_vectors']}",
    )
    checks.check(
        "metrics: U_A kept in the recall denominator (mixed)",
        metrics_block["methods"]["mixed"]["scores"]["recall"] < 1.0,
        "recall must be < 1 when a positive case abstains",
    )

    # --- (f) hash mismatch ----------------------------------------------------- #
    tmp = Path(tempfile.mkdtemp(prefix="rqc1-fixture-"))
    try:
        # the *frozen* mapping: real hash check
        real = harness.load_mapping()
        checks.check(
            "hash check: frozen mapping loads with the recorded sha256",
            real["sha256"] == harness.MAPPING_SHA256 and len(real["mapping"]) == 32,
            f"{real['sha256']}",
        )
        good = tmp / "mapping.md"
        good.write_text((REPO / "notes" / "collector-mapping-30cve.md").read_text(encoding="utf-8"), encoding="utf-8")
        sha = harness.sha256_file(good)
        try:
            harness.load_mapping(good, expected_sha=sha)
            checks.check("hash check: matching mapping hash loads", True, "")
        except harness.HashMismatch as exc:
            checks.check("hash check: matching mapping hash loads", False, str(exc))
        # tampered mapping fails hard
        good.write_text(good.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
        try:
            harness.load_mapping(good, expected_sha=sha)
            checks.check("hash check: tampered mapping fails hard", False, "no exception raised")
        except harness.HashMismatch as exc:
            checks.check("hash check: tampered mapping fails hard", True, str(exc)[:120])
        # wrong block count also fails hard
        short = tmp / "short.md"
        short.write_text("```yaml\nCVE-9000-0001: {}\n```\n", encoding="utf-8")
        try:
            harness.parse_mapping_text(short.read_text(encoding="utf-8"), expected_blocks=harness.N_CVE_SECTIONS_EXPECTED)
            checks.check("hash check: wrong block count fails hard", False, "no exception raised")
        except harness.HashMismatch as exc:
            checks.check("hash check: wrong block count fails hard", True, str(exc)[:120])
        # fixture mapping parses with the same parser (no block count expectation)
        checks.check(
            "same parser used for the fixture mapping",
            len(harness.parse_mapping_text(mapping_doc, expected_blocks=None)) == 12,
            "",
        )

        # snapshot: one-CVE manifest slice of the frozen snapshot, verified then tampered
        snap_src = REPO / "data" / "public-snapshot"
        snap_tmp = tmp / "public-snapshot"
        snap_tmp.mkdir()
        manifest = json.loads((snap_src / "manifest.json").read_text(encoding="utf-8"))
        keep = "CVE-2014-3704"
        sliced = dict(manifest)
        sliced["artifacts"] = {keep: manifest["artifacts"][keep]}
        (snap_tmp / "manifest.json").write_text(json.dumps(sliced, indent=1), encoding="utf-8")
        shutil.copytree(snap_src / keep, snap_tmp / keep)
        try:
            harness.verify_snapshot(snap_tmp)
            checks.check("hash check: clean snapshot slice verifies", True, "")
        except harness.HashMismatch as exc:
            checks.check("hash check: clean snapshot slice verifies", False, str(exc)[:160])
        tampered = snap_tmp / keep / "nvd.json"
        tampered.write_text(tampered.read_text(encoding="utf-8") + "\n ", encoding="utf-8")
        try:
            harness.verify_snapshot(snap_tmp)
            checks.check("hash check: tampered snapshot fails hard", False, "no exception raised")
        except harness.HashMismatch as exc:
            checks.check("hash check: tampered snapshot fails hard", True, str(exc)[:160])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # --- (g) versioncmp unit checks -------------------------------------------- #
    import versioncmp

    unit = [
        ("inclusive start matched", versioncmp.match_range("2.0", {"start_including": "2.0", "end_excluding": "3.0"})[0] is True),
        ("exclusive end rejected", versioncmp.match_range("3.0", {"start_including": "2.0", "end_excluding": "3.0"})[0] is False),
        ("inclusive end matched", versioncmp.match_range("3.0", {"start_including": "2.0", "end_including": "3.0"})[0] is True),
        ("exclusive start rejected", versioncmp.match_range("2.0", {"start_excluding": "2.0", "end_excluding": "3.0"})[0] is False),
        ("exact match", versioncmp.match_range("5.0", {"eq": "5.0", "strict_exact": True})[0] is True),
        ("exact non-match", versioncmp.match_range("5.0.1", {"eq": "5.0", "strict_exact": True})[0] is False),
        ("semver vs lexicographic", versioncmp.cmp_versions("1.10", "1.9") == 1 and versioncmp.cmp_versions("1.10", "1.9", mode="lex") == -1),
        ("prerelease sorts before release", versioncmp.cmp_versions("1.0-rc1", "1.0") == -1),
        ("distro revision scope mismatch -> not comparable", versioncmp.match_range("1.18.0", {"op": "lt", "version": "1.18.0-6ubuntu9"})[0] is None),
        ("line-scoped range", versioncmp.match_range("1.4.3", {"line": "1.4", "end_excluding": "1.4.4"})[0] is True),
        # out_of_scope: without the flag a line mismatch is False (a multi-line range is a
        # complete enumeration); with `out_of_scope: "unknown"` it is None (the source only
        # determines the named line, e.g. CVE-2023-2745).
        ("line mismatch without out_of_scope stays False (complete enumeration)",
         versioncmp.match_range("4.1.37", {"line": "6.2", "end_excluding": "6.2.1"})[0] is False),
        ("line mismatch with out_of_scope=unknown is None, not False (partial-scope advisory)",
         versioncmp.match_range("4.1.37", {"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"})[0] is None),
        ("out_of_scope=unknown reason states the line and the Unknown outcome",
         "outside the advisory-defined line 6.2" in versioncmp.match_range(
             "4.1.37", {"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"})[1]
         and "Unknown" in versioncmp.match_range(
             "4.1.37", {"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"})[1]),
        ("out_of_scope=unknown still matches a version on the named line",
         versioncmp.match_range("6.2.0", {"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"})[0] is True),
        ("out_of_scope=unknown still rejects the patched release of the named line",
         versioncmp.match_range("6.2.1", {"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"})[0] is False),
        ("out_of_scope=unknown inside a union does not make the union True",
         versioncmp.match_ranges("4.1.37", [{"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"}])[0] is None),
        ("zero padding equality", versioncmp.cmp_versions("5.0", "5.0.0") == 0),
        # documents *why* the fusion empty-range guard (review finding 2) is needed:
        # match_ranges() on an empty list reports False, i.e. a fabricated negative.
        ("an empty range list reports False (the reason for the fusion guard)", versioncmp.match_ranges("1.5", [])[0] is False),
    ]
    for name, ok in unit:
        checks.check(f"versioncmp: {name}", ok)

    # --- (h) 2026-10-15 review regressions on the real inputs ------------------- #
    # (h1) finding 1 — the status200 extractor must not claim a predicate the frozen
    #      capture cannot decide.  Same function that produces data/observations.json.
    import build_inputs  # module import only (main() is not called)

    spec200 = dict(regex=r"GET /wp-json/ -> (\d+)", kind="status200", product="WordPress")
    obs200 = build_inputs._observation(
        {"case_id": "status200-fixture"}, {"id": "probe_rest_root"}, "p_rest_reachable", "precondition",
        spec200, "200", "GET /wp-json/ -> 200", "batch3", "## 8711 (WP 4.7.1)")
    checks.check(
        "status200 extractor: status-only capture -> predicate Unknown (finding 1)",
        obs200["value_kind"] == "status200" and obs200["predicate_value"] is None
        and "routes" in obs200["predicate_reason"] and obs200["observed"] is True,
        f"predicate_value={obs200['predicate_value']!r}, reason={obs200['predicate_reason'][:80]!r}",
    )
    obs200_404 = build_inputs._observation(
        {"case_id": "status200-fixture"}, {"id": "probe_rest_root"}, "p_rest_reachable", "precondition",
        spec200, "404", "GET /wp-json/ -> 404", "batch3", "## 8711 (WP 4.7.1)")
    checks.check(
        "status200 extractor: 404 is also Unknown (never a decision from the status alone)",
        obs200_404["predicate_value"] is None,
        f"predicate_value={obs200_404['predicate_value']!r}",
    )

    # (h2) finding 4 — the regenerated advisory_ranges.json encodings
    real_adv = load_json(METHODS / "data" / "advisory_ranges.json")["cves"]
    r28121 = real_adv["CVE-2023-28121"]["ranges"]
    checks.check(
        "regenerated advisory: CVE-2023-28121 is a 9-branch union (not one span)",
        len(r28121) == 9 and all(set(r) == {"start_including", "end_excluding"} for r in r28121),
        f"{r28121}",
    )
    checks.check(
        "regenerated advisory: CVE-2023-28121 — 5.5.1 in range, 5.5.2 (patched mid-branch) out",
        _vc.match_ranges("5.5.1", r28121)[0] is True and _vc.match_ranges("5.5.2", r28121)[0] is False,
        f"5.5.1={_vc.match_ranges('5.5.1', r28121)[0]}, 5.5.2={_vc.match_ranges('5.5.2', r28121)[0]}",
    )
    checks.check(
        "regenerated advisory: CVE-2023-28121 — 5.6.1 in range, 5.6.2 out, 4.8.1 in range, 4.8.2 out",
        _vc.match_ranges("5.6.1", r28121)[0] is True and _vc.match_ranges("5.6.2", r28121)[0] is False
        and _vc.match_ranges("4.8.1", r28121)[0] is True and _vc.match_ranges("4.8.2", r28121)[0] is False,
        "",
    )
    r2745 = real_adv["CVE-2023-2745"]["ranges"]
    checks.check(
        "regenerated advisory: CVE-2023-2745 keeps only the 6.2 line, flagged out_of_scope=unknown (no borrowed 4.1.38 threshold)",
        r2745 == [{"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"}]
        and all(b.get("version") != "4.1.38" for b in r2745),
        f"{r2745}",
    )
    checks.check(
        "regenerated advisory: CVE-2023-2745 — 6.2.0 in range, 6.2.1 out, 4.1.37 exactly Unknown (not False / not claimed affected)",
        _vc.match_ranges("6.2.0", r2745)[0] is True and _vc.match_ranges("6.2.1", r2745)[0] is False
        and _vc.match_ranges("4.1.37", r2745)[0] is None,
        f"6.2.0={_vc.match_ranges('6.2.0', r2745)[0]}, 6.2.1={_vc.match_ranges('6.2.1', r2745)[0]}, "
        f"4.1.37={_vc.match_ranges('4.1.37', r2745)[0]!r}",
    )
    # The 6.2-only encoding is *partial scope*: the release post names the fixed 6.2.1 for
    # the 6.2 line while saying the older lines were updated too without stating their fixed
    # versions.  `out_of_scope: "unknown"` therefore makes a non-6.2 observed version
    # mechanically Unknown (the source does not determine it) instead of "outside the
    # advisory line" -> Not Applicable.  No benchmark case observes a non-6.2 version for
    # this CVE (the two cases are 6.2.0 / 6.2.1), so the change has no measured effect here;
    # the behaviour is covered by the synthetic CVE-9000-0013 cases below.

    # (h3) D-034 — the V2 captures lift 4 probes pending -> verified, so they are now
    #      accepted observations extracted from `experiments/methods/captures-v2/`.
    #      The 10924 probe must emit TWO conditions from ONE response (R4).
    real_obs = load_json(METHODS / "data" / "observations.json")
    for cid, ver in (("CVE-2017-1001000__vuln", "4.7.1"), ("CVE-2017-1001000__fixed", "4.7.2")):
        block = real_obs["cases"][cid]
        ob = next((o for o in block["observations"] if o.get("probe_id") == "probe_rest_root"), None)
        un = next((o for o in block["unobserved"] if o.get("probe_id") == "probe_rest_root"), None)
        checks.check(
            f"regenerated observations: {cid} route probe is an accepted 200+routes observation (D-034)",
            ob is not None and ob["condition_id"] == "p_rest_reachable" and ob["predicate_value"] is True
            and ob["value_kind"] == "rest_routes" and ob.get("body_has_routes") is True
            and un is None
            # the /wp-json/ text/html trap must not be the artifact used
            and ob["artifact_ref"].endswith("GET-rest-route-index-SUPPLEMENTARY.txt")
            and next((o["version"] for o in block["observations"] if o.get("value_kind") == "version"), None) == ver,
            f"accepted={ob and {k: ob.get(k) for k in ('condition_id', 'predicate_value', 'value_kind')}}, unobserved={un}",
        )
    # --- 10924: one request -> two mapped conditions, same predicate value (R4) ----
    for cid, expected in (("CVE-2024-10924__9_1_1_1_2fa_on", True),
                          ("CVE-2024-10924__9_1_1_1_2fa_off", False),
                          ("CVE-2024-10924__9_1_2_2fa_on_fixed", True)):
        block = real_obs["cases"][cid]
        twos = [o for o in block["observations"] if o.get("probe_id") == "probe_two_fa_route"]
        by_cond = {o["condition_id"]: o for o in twos}
        checks.check(
            f"regenerated observations: {cid} one probe_two_fa_route response emits BOTH "
            f"p_2fa_enabled and p_skip_onboarding_route = {expected} (R4: 1 request)",
            len(twos) == 2
            and set(by_cond) == {"p_2fa_enabled", "p_skip_onboarding_route"}
            and all(o["predicate_value"] is expected for o in twos)
            and all(o["artifact_ref"] == twos[0]["artifact_ref"] for o in twos)
            and by_cond["p_skip_onboarding_route"].get("shared_response_with") == "probe_two_fa_route"
            and not any(o.get("probe_id") == "probe_two_fa_route" for o in block["unobserved"]),
            f"records={[(o['condition_id'], o['predicate_value']) for o in twos]}, unobserved="
            f"{[o['probe_id'] for o in block['unobserved']]}",
        )
    # --- 3460: readme Stable tag (E5) + registration-form markers ------------------
    for cid, ver in (("CVE-2023-3460__vuln", "2.6.6"), ("CVE-2023-3460__fixed", "2.6.7")):
        block = real_obs["cases"][cid]
        rd = next((o for o in block["observations"] if o.get("probe_id") == "observe_plugin_readme_version"), None)
        fm = next((o for o in block["observations"] if o.get("probe_id") == "probe_um_register_form"), None)
        checks.check(
            f"regenerated observations: {cid} readme Stable tag -> E5 version {ver} (D-034)",
            rd is not None and rd.get("version") == ver and rd["predicate_value"] is True
            and ver in rd["artifact_line"] and "readme" in rd["artifact_ref"],
            f"readme={rd and {k: rd.get(k) for k in ('version', 'predicate_value', 'artifact_line')}}",
        )
        checks.check(
            f"regenerated observations: {cid} registration form -> p_open_registration_form True (D-034)",
            fm is not None and fm["condition_id"] == "p_open_registration_form" and fm["predicate_value"] is True
            and all(fm.get("form_markers", {}).values())
            and not any(o.get("probe_id") == "probe_um_register_form" for o in block["unobserved"]),
            f"form={fm and {k: fm.get(k) for k in ('predicate_value', 'form_markers')}}",
        )
    # The fixed-state 3460 artifact must be the *superseding* re-capture (aligned fixture),
    # not the STALE pre-fix `?page_id=12` file whose form id is 6.
    fixed_form = next(o for o in real_obs["cases"]["CVE-2023-3460__fixed"]["observations"]
                      if o.get("probe_id") == "probe_um_register_form")
    checks.check(
        "regenerated observations: 3460 fixed state uses the aligned page_id6 re-capture (not the STALE page_id12 file)",
        fixed_form["artifact_ref"].endswith("8831-um267-GET-page_id6-AS-SPECIFIED.txt"),
        f"{fixed_form['artifact_ref']}",
    )
    checks.check(
        "regenerated observations: build counts (top-up 2026-10-17: 56 requests -> 59 records, 3 shared-response "
        "extractions, 77 G7)",
        real_obs["counts"]["verified_probe_requests"] == 56
        and real_obs["counts"]["accepted_observations"] == 59
        and real_obs["counts"]["extra_condition_extractions"] == 3
        and real_obs["counts"]["unobserved_entries"] == 77,
        f"{real_obs['counts']}",
    )
    # --- V2 extractor unit checks (mutation-sensitive: a reverted kind breaks these) --
    def _obs(kind, value, body, regex):
        return build_inputs._observation(
            {"case_id": "v2-extractor-fixture"}, {"id": "probe_x"}, "p_x", "precondition",
            {"regex": regex, "kind": kind, "product": "ultimate-member"}, value,
            f"HTTP/2 000 fixture line {value}", "pilot", None, body)

    rr_true = _obs("rest_routes", "200", '{"namespaces":["wp/v2"],"routes":{"\\/wp\\/v2":{}}}', r"HTTP/1\.[01]\s+(\d{3})")
    rr_false = _obs("rest_routes", "200", "<html>front page fallback, no REST index</html>", r"HTTP/1\.[01]\s+(\d{3})")
    rr_404 = _obs("rest_routes", "404", '{"code":"rest_no_route"}', r"HTTP/1\.[01]\s+(\d{3})")
    checks.check(
        "V2 extractor: rest_routes — 200+routes True; 200 without routes False; 404 Unknown",
        rr_true["predicate_value"] is True and rr_false["predicate_value"] is False
        and rr_404["predicate_value"] is None,
        f"200+routes={rr_true['predicate_value']}, 200-plain={rr_false['predicate_value']}, 404={rr_404['predicate_value']}",
    )
    rt_400 = _obs("rest_route_presence", "400", '{"code":"rest_missing_callback_param"}', r"HTTP/1\.[01]\s+(\d{3})")
    rt_404 = _obs("rest_route_presence", "404", '{"code":"rest_no_route"}', r"HTTP/1\.[01]\s+(\d{3})")
    rt_200 = _obs("rest_route_presence", "200", "<html>front page</html>", r"HTTP/1\.[01]\s+(\d{3})")
    checks.check(
        "V2 extractor: rest_route_presence — 400 rest_missing_callback_param True; 404 rest_no_route False; 200 Unknown",
        rt_400["predicate_value"] is True and rt_404["predicate_value"] is False
        and rt_200["predicate_value"] is None,
        f"400={rt_400['predicate_value']}, 404={rt_404['predicate_value']}, 200={rt_200['predicate_value']}",
    )
    fm_true = _obs("form_markers", "200", '<form class="um-form">user_login-7 <input name="_wpnonce">', r"HTTP/1\.[01]\s+(\d{3})")
    fm_false = _obs("form_markers", "200", '<form class="um-form">user_login-6 <input name="_wpnonce">', r"HTTP/1\.[01]\s+(\d{3})")
    fm_404 = _obs("form_markers", "404", "not found", r"HTTP/1\.[01]\s+(\d{3})")
    checks.check(
        "V2 extractor: form_markers — 200 + um-form + user_login-7 + _wpnonce True; wrong form id False; 404 Unknown",
        fm_true["predicate_value"] is True and fm_false["predicate_value"] is False
        and fm_404["predicate_value"] is None,
        f"aligned={fm_true['predicate_value']}, page_id12={fm_false['predicate_value']}, 404={fm_404['predicate_value']}",
    )
    # shared-response record helper (the 10924 two-predicate fix) — mutation-sensitive
    shared = build_inputs._shared_extraction(rt_400, "p_skip_onboarding_route", "precondition")
    checks.check(
        "V2 extractor: _shared_extraction copies artifact provenance, retargets the condition (R4)",
        shared["condition_id"] == "p_skip_onboarding_route" and shared["predicate_value"] is True
        and shared["artifact_ref"] == rt_400["artifact_ref"] and shared["shared_response_with"] == "probe_x"
        and "R4" in shared["predicate_reason"],
        f"{ {k: shared.get(k) for k in ('condition_id', 'predicate_value', 'shared_response_with')} }",
    )
    # the real-data types/statuses: v2 probes are `verified`, and the D-033 requests are recorded
    real_mapping = harness.load_mapping()["mapping"]
    probes = {p["id"]: p for p in ((real_mapping["CVE-2017-1001000"].get("method") or {}).get("probes") or [])}
    checks.check(
        "regenerated observations: the three V2 probes are `verified` in the frozen mapping with the D-033 requests",
        probes["probe_rest_root"]["validation"]["status"] == "verified"
        and probes["probe_rest_root"]["request"]["path"] == "/?rest_route=/"
        and (lambda p: p["validation"]["status"] == "verified"
             and p["request"]["path"] == "/?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding"
             and p["request"]["method"] == "POST")(
            {p["id"]: p for p in ((real_mapping["CVE-2024-10924"].get("method") or {}).get("probes") or [])}["probe_two_fa_route"])
        and all(p["validation"]["status"] == "verified" for p in (real_mapping["CVE-2023-3460"]["method"]["probes"])),
        "probe statuses/requests read from the frozen mapping",
    )

    # --- (h5) top-up 2026-10-17: mapping rulings, 2nd snapshot cohort, JSON advisory --
    real_mapping = harness.load_mapping()["mapping"]
    checks.check(
        "top-up mapping: CVE-2023-23752 path = [p_config_object_readable] only (subsumed conditions out)",
        [p["all_of"] for p in real_mapping["CVE-2023-23752"]["reference"]["paths"]] == [["p_config_object_readable"]]
        and "p_webservices_config_enabled" not in json.dumps(real_mapping["CVE-2023-23752"]["reference"]["paths"])
        and "p_api_entry_reachable" not in json.dumps(real_mapping["CVE-2023-23752"]["reference"]["paths"]),
        f"{real_mapping['CVE-2023-23752']['reference']['paths']}",
    )
    checks.check(
        "top-up mapping: CVE-2023-6553 path = [p_plugin_files_present]; activation/filter wrapper documented only",
        [p["all_of"] for p in real_mapping["CVE-2023-6553"]["reference"]["paths"]] == [["p_plugin_files_present"]]
        and "p_php_filter_wrapper" not in json.dumps(real_mapping["CVE-2023-6553"]["reference"]["paths"])
        and "p_plugin_active" not in json.dumps(real_mapping["CVE-2023-6553"]["reference"]["paths"])
        and real_mapping["CVE-2023-6553"]["reference"]["conditions"]["p_php_filter_wrapper"]["kind"] == "build",
        f"{real_mapping['CVE-2023-6553']['reference']['paths']}",
    )
    probe_6553 = {p["id"]: p for p in real_mapping["CVE-2023-6553"]["method"]["probes"]}
    checks.check(
        "top-up mapping: 6553 reachability probe is one-sided (no false_when) and benign (no filter chain)",
        "false_when" not in probe_6553["probe_direct_file_reachable"]["interpret"]
        and "php://filter" not in json.dumps(probe_6553["probe_direct_file_reachable"]["request"])
        and "0 byte" in probe_6553["probe_direct_file_reachable"]["interpret"]["true_when"],
        f"{probe_6553['probe_direct_file_reachable']['interpret'].keys()}",
    )
    # both snapshot cohorts verified and merged (no CVE in two cohorts)
    snap = harness.load_snapshot()
    checks.check(
        "top-up snapshot: both cohorts verified (rc 0), merged n_cves=32, cohort tagged per CVE",
        snap["n_cves"] == 32
        and [c["snapshot_date"] for c in snap["cohorts"]] == ["2026-10-11", "2026-10-17"]
        and all(c["verification"]["returncode"] == 0 for c in snap["cohorts"])
        and snap["snapshot"]["CVE-2023-6553"]["_cohort_dir"] == "data/public-snapshot-2026-10-17"
        and snap["snapshot"]["CVE-2014-3704"]["_cohort_dir"] == "data/public-snapshot",
        f"n_cves={snap['n_cves']}, cohorts={[c['snapshot_date'] for c in snap['cohorts']]}",
    )
    # advisory: vendor HTML for 23752, CVE.org CNA JSON for 6553 (ruling #8)
    r23752 = real_adv["CVE-2023-23752"]["ranges"]
    checks.check(
        "top-up advisory: CVE-2023-23752 = 4.0.0-4.2.7 from the vendor page (4.2.7 in, 4.2.8 out)",
        r23752 == [{"start_including": "4.0.0", "end_including": "4.2.7"}]
        and _vc.match_ranges("4.2.7", r23752)[0] is True and _vc.match_ranges("4.2.8", r23752)[0] is False
        and real_adv["CVE-2023-23752"]["artifact"].startswith("data/public-snapshot-2026-10-17/"),
        f"{r23752}",
    )
    adv6553 = real_adv["CVE-2023-6553"]
    checks.check(
        "top-up advisory: CVE-2023-6553 parsed from the CVE.org CNA JSON (<=1.3.7; 1.3.8 out) + fixed-version provenance",
        adv6553["extraction_kind"] == "cna_affected_versions_json"
        and adv6553["ranges"] == [{"start_including": "0", "end_including": "1.3.7"}]
        and _vc.match_ranges("1.3.7", adv6553["ranges"])[0] is True
        and _vc.match_ranges("1.3.8", adv6553["ranges"])[0] is False
        and adv6553["fixed_version_provenance"]["fixed_version"] == "1.3.8"
        and adv6553["artifact"].endswith("CVE-2023-6553/advisory-fallback.json"),
        f"{adv6553['ranges']}, kind={adv6553['extraction_kind']}",
    )
    # JSON branch unit checks (mutation-sensitive: a missing `lessThanOrEqual` branch fails them)
    with tempfile.TemporaryDirectory() as td:
        synth = Path(td) / "cna.json"
        synth.write_text(json.dumps({
            "cveMetadata": {"cveId": "CVE-9000-0099"},
            "containers": {"cna": {"title": "Synthetic <= 1.3.7",
                                   "affected": [{"versions": [
                                       {"version": "0", "status": "affected", "lessThanOrEqual": "1.3.7",
                                        "versionType": "semver"},
                                       {"version": "1.3.8", "status": "unaffected"}]}]}},
        }), encoding="utf-8")
        got = build_inputs.cna_affected_from_json(synth, "CVE-9000-0099")
        checks.check(
            "cna_affected_from_json: lessThanOrEqual -> inclusive upper bound; unaffected entries ignored",
            got["ranges"] == [{"start_including": "0", "end_including": "1.3.7"}]
            and len(got["literals"]) == 1 and got["literals"][0]["status"] == "affected",
            f"{got['ranges']}",
        )
        none = Path(td) / "none.json"
        none.write_text(json.dumps({
            "cveMetadata": {"cveId": "CVE-9000-0099"},
            "containers": {"cna": {"affected": [{"versions": [{"version": "1.0", "status": "unaffected"}]}]}},
        }), encoding="utf-8")
        raised = False
        try:
            build_inputs.cna_affected_from_json(none, "CVE-9000-0099")
        except SystemExit:
            raised = True
        checks.check("cna_affected_from_json: no affected range -> hard failure (never a guessed range)", raised, "")
    # observations for the 5 top-up cases
    jl427 = real_obs["cases"]["CVE-2023-23752__4_2_7_default"]
    v427 = next(o for o in jl427["observations"] if o["probe_id"] == "observe_joomla_version")
    c427 = next(o for o in jl427["observations"] if o["probe_id"] == "probe_config_application_public")
    checks.check(
        "top-up observations: Joomla 4.2.7 -> E5 4.2.7 + disclosure True (JConfig keys; secret keys recorded, not required)",
        v427["version"] == "4.2.7" and v427["predicate_value"] is True
        and c427["predicate_value"] is True and all(c427["jconfig_min_keys"].values())
        and c427["jconfig_secret_keys_present"]["password"] is True
        and "canary" not in json.dumps(c427.get("extraction_rule", "")) and not jl427["unobserved"],
        f"v={v427['version']}, c={c427['predicate_value']}, keys={c427.get('jconfig_min_keys')}",
    )
    jl428 = real_obs["cases"]["CVE-2023-23752__4_2_8_default_fixed"]
    v428 = next(o for o in jl428["observations"] if o["probe_id"] == "observe_joomla_version")
    c428 = next(o for o in jl428["observations"] if o["probe_id"] == "probe_config_application_public")
    checks.check(
        "top-up observations: Joomla 4.2.8 -> E5 4.2.8 + disclosure False (401 application-level envelope)",
        v428["version"] == "4.2.8" and c428["predicate_value"] is False and not jl428["unobserved"],
        f"v={v428['version']}, c={c428['predicate_value']}",
    )
    for cid, ver in (("CVE-2023-6553__1_3_7_active", "1.3.7"),
                     ("CVE-2023-6553__1_3_7_inactive", "1.3.7"),
                     ("CVE-2023-6553__1_3_8_active_fixed", "1.3.8")):
        block = real_obs["cases"][cid]
        rd = next(o for o in block["observations"] if o["probe_id"] == "observe_plugin_readme_version")
        fr = next(o for o in block["observations"] if o["probe_id"] == "probe_direct_file_reachable")
        checks.check(
            f"top-up observations: {cid} -> readme Stable tag {ver} + reachability True (HTTP 200, 0-byte body)",
            rd["version"] == ver and rd["predicate_value"] is True
            and fr["predicate_value"] is True and fr.get("response_bytes") == 0
            and not block["unobserved"],
            f"readme={rd['version']}, reachable={fr['predicate_value']}, bytes={fr.get('response_bytes')}",
        )
    checks.check(
        "top-up observations: the 1.3.7 inactive readme reuse is declared (artifact_state_note), not a second capture",
        "artifact_state_note" in next(o for o in real_obs["cases"]["CVE-2023-6553__1_3_7_inactive"]["observations"]
                                      if o["probe_id"] == "observe_plugin_readme_version"),
        "",
    )
    # end-to-end: the 5 top-up cases are decidable, in the direction the labels imply
    real_cases = load_json(METHODS / "data" / "cases.json")["cases"]
    real_ctx = harness.build_context(real_mapping, snap["snapshot"], real_adv, real_obs["cases"], real_cases)
    topup_cases = [c for c in real_cases if c["cve_id"] in ("CVE-2023-23752", "CVE-2023-6553")]
    preds = {c["case_id"]: {m: harness.methods_mod.run_method(m, harness.case_view(c), real_ctx)["prediction"]
                            for m in harness.methods_mod.METHODS}
             for c in topup_cases}
    for cid, expected_fusion, lvl1, adv_expected in (
            ("CVE-2023-23752__4_2_7_default", "Applicable", "Applicable", "Unknown"),
            ("CVE-2023-23752__4_2_8_default_fixed", "Not Applicable", "Not Applicable", "Not Applicable"),
            ("CVE-2023-6553__1_3_7_active", "Applicable", "Applicable", "Unknown"),
            ("CVE-2023-6553__1_3_7_inactive", "Applicable", "Applicable", "Unknown"),
            ("CVE-2023-6553__1_3_8_active_fixed", "Not Applicable", "Not Applicable", "Not Applicable")):
        p = preds[cid]
        checks.check(
            f"top-up predictions: {cid} fusion={expected_fusion}, level-1={lvl1}, advisory_only={adv_expected}",
            p["fusion"] == expected_fusion
            and all(p[m] == lvl1 for m in ("cpe_only", "nvd_only", "http_version_only"))
            and p["advisory_only"] == adv_expected,
            f"{p}",
        )

    # (h4) finding 5 — check mode must not compute metrics
    chk_dir = Path(tempfile.mkdtemp(prefix="rqc1-check-"))
    try:
        rep = harness.mode_check(chk_dir)
        checks.check(
            "harness.mode_check: no benchmark result written and no metric computed (finding 5)",
            rep.get("benchmark_result_written") is False
            and rep.get("metrics_computed") is False
            and rep.get("metric_code_invoked") is False
            and rep.get("all_predictions_in_allowed_set") is True
            and rep.get("label_isolation_preserved") is True
            and not (chk_dir / "metrics.json").exists()
            and not (chk_dir / "predictions.json").exists(),
            json.dumps({k: rep.get(k) for k in ("benchmark_result_written", "metrics_computed", "metric_code_invoked")}),
        )
    except Exception as exc:  # noqa: BLE001
        checks.check(
            "harness.mode_check: no benchmark result written and no metric computed (finding 5)",
            False, repr(exc)[:200],
        )
    finally:
        shutil.rmtree(chk_dir, ignore_errors=True)


    # --- write outputs ---------------------------------------------------------- #
    run_metadata = {
        "mode": "fixture (synthetic; not the benchmark)",
        "harness": "experiments/methods/fixture/run_fixture.py",
        "inputs": {
            "mapping": {"path": "experiments/methods/fixture/fixture_mapping.md", "sha256": harness.sha256_file(FIXTURE_DIR / "fixture_mapping.md")},
            "cases": {"path": "experiments/methods/fixture/fixture_cases.json", "sha256": harness.sha256_file(FIXTURE_DIR / "fixture_cases.json")},
            "observations": {"path": "experiments/methods/fixture/fixture_observations.json", "sha256": harness.sha256_file(FIXTURE_DIR / "fixture_observations.json")},
            "advisory_ranges": {"path": "experiments/methods/fixture/fixture_advisory_ranges.json", "sha256": harness.sha256_file(FIXTURE_DIR / "fixture_advisory_ranges.json")},
        },
        "labels_visible_to_methods": False,
    }
    harness.write_outputs(out_dir, per_method, records, metrics_mod.evaluate(per_method, cases), run_metadata)
    (out_dir / "fixture-report.json").write_text(
        json.dumps({"summary": checks.summary(), "checks": checks.results, "metrics_on_fixture": metrics_mod.evaluate(per_method, cases)}, indent=1, ensure_ascii=False),
        encoding="utf-8",
    )
    summary = checks.summary()
    print(f"fixture checks: {summary['n_pass']}/{summary['n_checks']} pass, {summary['n_fail']} fail")
    for r in checks.results:
        if not r["pass"]:
            print(f"  FAIL {r['check']}: {r['detail']}")
    print(f"outputs written under {out_dir}")
    return 0 if summary["n_fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT_DEFAULT))
