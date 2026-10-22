#!/usr/bin/env python3
"""harness.py — evaluation harness for RQ-C1 step 3 (D-026 / D-030).

Loads the frozen inputs with **hash verification**, runs the five methods per case,
attaches the ground-truth labels only *after* prediction, and emits
``predictions.json`` / ``metrics.json`` / ``run-metadata.json``.

Usage
-----
    python3 harness.py load                 # hash checks + case enumeration (safe, no benchmark)
    python3 harness.py benchmark --run-benchmark   # STEP 4 ONLY — real comparison run
    python3 harness.py fixture              # synthetic fixture through the same code path

Inputs (frozen, never edited by this tool):

* ``notes/collector-mapping-30cve.md``            — D-030 freeze, **amended by D-032/D-033/D-034** and by the
  2026-10-17 top-up (D-035/D-036 + `reviews/Review_mapping_topup_phanquyet_2026-10-17.md`; 32 CVE blocks,
  freeze of the 32-CVE version = D-037 pending), sha256 c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c
* ``data/public-snapshot/``                       — D-026 cohort, verified against ``manifest.json``
* ``data/public-snapshot-2026-10-17/``            — D-035 top-up cohort, verified against its own ``manifest.json``
* ``experiments/methods/data/cases.json``         — case list + ground-truth labels (M2)
* ``experiments/methods/data/observations.json``  — accepted E5/E6 observations (M1)
* ``experiments/methods/data/advisory_ranges.json``— normalised advisory ranges (M3)

Guarantees enforced here
------------------------
1. Mapping sha256 and **both** snapshot manifests are verified on load; a mismatch is a
   hard failure (:class:`HashMismatch`) and no prediction is produced.
2. Methods receive a **label-free, config-free case view** (allowlist in
   :func:`case_view`); labels are joined only in the scoring step.
3. Per-case predictions are written separately from the metric table.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

import metrics as metrics_mod
import methods as methods_mod

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

MAPPING_PATH = REPO / "notes" / "collector-mapping-30cve.md"
#: Snapshot cohorts (frozen, separate manifests): the 2026-10-11 D-026 cohort and the
#: 2026-10-17 D-035 top-up cohort.  Both are verified on load; neither is modified.
SNAPSHOT_DIR = REPO / "data" / "public-snapshot"
SNAPSHOT_COHORT_2026_10_17 = REPO / "data" / "public-snapshot-2026-10-17"
SNAPSHOT_DIRS = (SNAPSHOT_DIR, SNAPSHOT_COHORT_2026_10_17)
VERIFY_SNAPSHOT = REPO / "experiments" / "public-snapshot" / "verify_snapshot.py"
DATA_DIR = HERE / "data"
DEFAULT_OUT = HERE / "output"

#: Mapping freeze hash: D-030 as amended by D-032 (route probe verified -> pending),
#: D-033 (two probe request paths corrected), D-034 (4 V2 captures -> verified) and the
#: 2026-10-17 top-up (D-035/D-036 + `reviews/Review_mapping_topup_phanquyet_2026-10-17.md`:
#: 2 CVE blocks merged into the same file => 32 blocks, 4 probes verified, the 23752 path
#: reduced to `[p_config_object_readable]` and the 6553 path to `[p_plugin_files_present]`).
#: Freeze of this 32-CVE version = D-037 (pending).
MAPPING_SHA256 = "c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c"

#: method-visible case fields (allowlist) — no label, no build, no config internals.
CASE_VIEW_KEYS = ("case_id", "cve_id", "product_key", "cpe_vendor_product", "identity_tokens", "identity_family")

N_CVE_SECTIONS_EXPECTED = 32


class HashMismatch(RuntimeError):
    """Raised when a frozen input does not match its recorded hash/version."""


# --------------------------------------------------------------------------- #
# loading + integrity
# --------------------------------------------------------------------------- #
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_mapping_text(text: str, expected_blocks: int = N_CVE_SECTIONS_EXPECTED) -> dict:
    """Parse the ```yaml blocks of a collector/mapping file.

    ``expected_blocks`` is asserted when given (the frozen benchmark mapping must
    carry exactly 32 blocks); the fixture passes ``None``.
    """
    blocks = re.findall(r"```yaml\n(.*?)```", text, re.S)
    mapping: dict = {}
    for block in blocks:
        parsed = yaml.safe_load(block)
        if not isinstance(parsed, dict):
            raise HashMismatch("mapping block did not parse to a mapping")
        for key, value in parsed.items():
            if key in mapping:
                raise HashMismatch(f"duplicate CVE block {key}")
            mapping[key] = value
    if expected_blocks is not None and len(mapping) != expected_blocks:
        raise HashMismatch(f"expected {expected_blocks} CVE blocks, parsed {len(mapping)}")
    return mapping


def load_mapping(path: Path = MAPPING_PATH, expected_sha: str = MAPPING_SHA256) -> dict:
    path = Path(path)
    if not path.exists():
        raise HashMismatch(f"mapping not found: {path}")
    actual = sha256_file(path)
    if expected_sha and actual != expected_sha:
        raise HashMismatch(f"mapping sha256 mismatch: expected {expected_sha}, actual {actual} ({path})")
    mapping = parse_mapping_text(path.read_text(encoding="utf-8"))
    return {"path": str(path.relative_to(REPO) if REPO in path.parents else path), "sha256": actual, "mapping": mapping}


def verify_snapshot(snapshot_dir: Path = SNAPSHOT_DIR) -> dict:
    """Run the frozen snapshot verifier; a non-zero exit is a hard failure."""
    snapshot_dir = Path(snapshot_dir)
    cmd = [sys.executable, str(VERIFY_SNAPSHOT), "--dir", str(snapshot_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    rel = snapshot_dir.relative_to(REPO) if REPO in snapshot_dir.resolve().parents else snapshot_dir
    report = {
        "dir": str(rel),
        "command": f"python3 experiments/public-snapshot/verify_snapshot.py --dir {rel}",
        "returncode": proc.returncode,
        "output": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }
    if proc.returncode != 0:
        raise HashMismatch(f"snapshot verification failed ({rel}, rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return report


def load_snapshot(snapshot_dir: Path = None, verify: bool = True) -> dict:
    """Load and merge the snapshot cohorts, verifying **every** manifest.

    Each cohort keeps its own manifest/hash/provenance in the returned ``cohorts``
    list; the merged ``snapshot`` dict tags each CVE with the cohort directory it came
    from so provenance strings in the method output point at the real artifact root.
    A CVE present in both cohorts is a hard failure (no silent shadowing).
    """
    dirs = list(SNAPSHOT_DIRS) if snapshot_dir is None else [Path(snapshot_dir)]
    snapshot: dict = {}
    cohorts = []
    for cohort in dirs:
        cohort = Path(cohort)
        report = verify_snapshot(cohort) if verify else {"skipped": True}
        manifest_path = cohort / "manifest.json"
        if not manifest_path.exists():
            raise HashMismatch(f"snapshot manifest not found: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        rel_dir = str(cohort.relative_to(REPO)) if REPO in cohort.resolve().parents else str(cohort)
        n_here = 0
        for cve_dir in sorted(p for p in cohort.iterdir() if p.is_dir()):
            cve = cve_dir.name
            if cve in snapshot:
                raise HashMismatch(f"CVE {cve} present in more than one snapshot cohort")
            entry = {}
            for kind, name in (("cpe", "cpe.json"), ("nvd", "nvd.json")):
                f = cve_dir / name
                if f.exists():
                    entry[kind] = json.loads(f.read_text(encoding="utf-8"))
            if entry:
                entry["_cohort_dir"] = rel_dir
                snapshot[cve] = entry
                n_here += 1
        cohorts.append({
            "dir": rel_dir,
            "manifest_path": str(manifest_path.relative_to(REPO)) if REPO in manifest_path.resolve().parents else str(manifest_path),
            "manifest_sha256": sha256_file(manifest_path),
            "snapshot_date": manifest.get("snapshot_date"),
            "cohort": manifest.get("cohort"),
            "n_cves_loaded": n_here,
            "verification": report,
        })
    primary = cohorts[0] if cohorts else {}
    return {
        "dir": primary.get("dir"),
        "manifest_path": primary.get("manifest_path"),
        "manifest_sha256": primary.get("manifest_sha256"),
        "snapshot_date": " + ".join(str(c.get("snapshot_date")) for c in cohorts),
        "n_cves": len(snapshot),
        "cohorts": cohorts,
        "verification": [c["verification"] for c in cohorts],
        "snapshot": snapshot,
    }


def load_json(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise HashMismatch(f"required input not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# dataset + run
# --------------------------------------------------------------------------- #
def case_view(case: dict) -> dict:
    """Return the method-visible projection of a case (no label, build, config)."""
    view = {k: case[k] for k in CASE_VIEW_KEYS if k in case}
    if "product_key" not in view and "cpe_vendor_product" in case:
        view["product_key"] = case["cpe_vendor_product"]
    return view


def build_context(mapping: dict, snapshot: dict, advisory_ranges: dict, observations: dict, cases: list) -> methods_mod.Context:
    cases_meta = {c["case_id"]: {k: v for k, v in c.items() if k not in methods_mod.FORBIDDEN_CASE_KEYS} for c in cases}
    return methods_mod.Context(mapping, snapshot, advisory_ranges, observations, cases_meta)


def predict_all(ctx: methods_mod.Context, cases: list, methods=None) -> dict:
    """Run every method on every case.  Method input = label-free case view."""
    methods = list(methods or methods_mod.METHODS)
    per_method = {m: {} for m in methods}
    records = []
    for case in cases:
        view = case_view(case)
        for method in methods:
            rec = methods_mod.run_method(method, view, ctx)
            per_method[method][case["case_id"]] = rec["prediction"]
            records.append(rec)
    return per_method, records


def METHODS_LIST():
    return list(methods_mod.METHODS)


def development_groups(cases: list, mapping: dict) -> dict:
    """Group case ids by the per-CVE `development_use` flags (spec §9)."""
    groups = {"rule_development": [], "signal_development": [], "no_development": []}
    for case in cases:
        flags = ((mapping.get(case["cve_id"]) or {}).get("development_use") or {})
        if flags.get("used_for_rule_development"):
            groups["rule_development"].append(case["case_id"])
        elif flags.get("used_for_signal_development"):
            groups["signal_development"].append(case["case_id"])
        else:
            groups["no_development"].append(case["case_id"])
    return groups


def scenario_groups(cases: list) -> dict:
    groups: dict = {}
    for case in cases:
        for tag in case.get("scenario_tags") or []:
            groups.setdefault(f"tag:{tag}", []).append(case["case_id"])
    return groups


def evaluate(mapping: dict, snapshot: dict, advisory_ranges: dict, observations: dict, cases: list) -> dict:
    ctx = build_context(mapping, snapshot, advisory_ranges, observations, cases)
    per_method, records = predict_all(ctx, cases)
    groups = development_groups(cases, mapping)
    groups.update(scenario_groups(cases))
    report = metrics_mod.evaluate(per_method, cases, groups)
    return {"ctx": ctx, "per_method": per_method, "records": records, "metrics": report}


def write_outputs(out_dir: Path, per_method: dict, records: list, metrics_block: dict, run_metadata: dict) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "predictions.json").write_text(
        json.dumps({"per_case_records": records, "per_method_predictions": per_method}, indent=1, ensure_ascii=False),
        encoding="utf-8",
    )
    (out_dir / "metrics.json").write_text(json.dumps(metrics_block, indent=1, ensure_ascii=False), encoding="utf-8")
    (out_dir / "run-metadata.json").write_text(json.dumps(run_metadata, indent=1, ensure_ascii=False), encoding="utf-8")
    return {"predictions": str(out_dir / "predictions.json"), "metrics": str(out_dir / "metrics.json"), "run_metadata": str(out_dir / "run-metadata.json")}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# modes
# --------------------------------------------------------------------------- #
def mode_load(out_dir: Path = DEFAULT_OUT) -> dict:
    """Hash checks + case enumeration only.  Produces run metadata, no predictions."""
    mapping_info = load_mapping()
    snapshot_info = load_snapshot()
    cases_doc = load_json(DATA_DIR / "cases.json")
    observations = load_json(DATA_DIR / "observations.json")
    advisory = load_json(DATA_DIR / "advisory_ranges.json")
    cases = cases_doc["cases"]
    run_metadata = {
        "mode": "load-check (no benchmark run)",
        "generated_at_utc": now_utc(),
        "harness": "experiments/methods/harness.py",
        "mapping": {"path": mapping_info["path"], "sha256": mapping_info["sha256"], "expected_sha256": MAPPING_SHA256, "n_cve_blocks": len(mapping_info["mapping"])},
        "snapshot": {
            "dir": snapshot_info["dir"],
            "manifest_path": snapshot_info["manifest_path"],
            "manifest_sha256": snapshot_info["manifest_sha256"],
            "snapshot_date": snapshot_info["snapshot_date"],
            "n_cves": snapshot_info["n_cves"],
            "cohorts": snapshot_info["cohorts"],
            "verification": snapshot_info["verification"],
        },
        "method_inputs": {
            "cases": {"path": "experiments/methods/data/cases.json", "sha256": sha256_file(DATA_DIR / "cases.json")},
            "observations": {"path": "experiments/methods/data/observations.json", "sha256": sha256_file(DATA_DIR / "observations.json")},
            "advisory_ranges": {"path": "experiments/methods/data/advisory_ranges.json", "sha256": sha256_file(DATA_DIR / "advisory_ranges.json")},
        },
        "counts": {**cases_doc["counts"], "n_observation_cases": len(observations["cases"])},
        "methods": METHODS_LIST(),
        "installed_package_metadata_used": False,
        "labels_visible_to_methods": False,
    }
    snp = snapshot_info["snapshot"]
    for case in cases:
        if case["cve_id"] not in snp:
            raise HashMismatch(f"case {case['case_id']}: CVE {case['cve_id']} missing from snapshot")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "run-metadata.json").write_text(json.dumps(run_metadata, indent=1, ensure_ascii=False), encoding="utf-8")
    return run_metadata


def mode_benchmark(out_dir: Path = DEFAULT_OUT) -> dict:
    mapping_info = load_mapping()
    snapshot_info = load_snapshot()
    cases_doc = load_json(DATA_DIR / "cases.json")
    observations = load_json(DATA_DIR / "observations.json")["cases"]
    advisory = load_json(DATA_DIR / "advisory_ranges.json")["cves"]
    cases = cases_doc["cases"]
    result = evaluate(mapping_info["mapping"], snapshot_info["snapshot"], advisory, observations, cases)
    run_metadata = {
        "mode": "benchmark",
        "generated_at_utc": now_utc(),
        "mapping": {"path": mapping_info["path"], "sha256": mapping_info["sha256"], "expected_sha256": MAPPING_SHA256},
        "snapshot": {"manifest_sha256": snapshot_info["manifest_sha256"], "snapshot_date": snapshot_info["snapshot_date"],
                     "cohorts": snapshot_info["cohorts"], "verification": snapshot_info["verification"]},
        "method_inputs": {
            "cases": {"path": "experiments/methods/data/cases.json", "sha256": sha256_file(DATA_DIR / "cases.json")},
            "observations": {"path": "experiments/methods/data/observations.json", "sha256": sha256_file(DATA_DIR / "observations.json")},
            "advisory_ranges": {"path": "experiments/methods/data/advisory_ranges.json", "sha256": sha256_file(DATA_DIR / "advisory_ranges.json")},
        },
        "counts": cases_doc["counts"],
        "labels_visible_to_methods": False,
    }
    files = write_outputs(out_dir, result["per_method"], result["records"], result["metrics"], run_metadata)
    return {"metrics": result["metrics"], "files": files, "run_metadata": run_metadata}


def mode_check(out_dir: Path = DEFAULT_OUT) -> dict:
    """Structural check: run the methods on the real inputs, assert invariants, emit no result.

    This is the pre-step-4 gate.  It deliberately does **not** write predictions or
    metrics (no accuracy number is computed or inspected here); it only proves the
    harness executes on the frozen inputs, that every prediction is in
    {Applicable, Not Applicable, Unknown}, that predictions are invariant under a
    label swap, and that every record carries reasons/evidence/provenance.

    History note (2026-10-15, review finding 5): earlier versions of ``mode_check``
    routed through :func:`evaluate`, which calls ``metrics.evaluate`` and therefore
    computed the real confusion/precision/recall/F1 in memory (never written to
    disk, but computed).  That contradicted this docstring.  This version calls
    :func:`build_context` + :func:`predict_all` and never invokes the metric code
    (``metrics.computed`` is reported as ``False``).
    """
    mapping_info = load_mapping()
    snapshot_info = load_snapshot()
    cases_doc = load_json(DATA_DIR / "cases.json")
    observations = load_json(DATA_DIR / "observations.json")["cases"]
    advisory = load_json(DATA_DIR / "advisory_ranges.json")["cves"]
    cases = cases_doc["cases"]

    ctx = build_context(mapping_info["mapping"], snapshot_info["snapshot"], advisory, observations, cases)
    per_method, records = predict_all(ctx, cases)

    allowed = set(metrics_mod.PREDICTIONS)
    bad = [(r["case_id"], r["method"], r["prediction"]) for r in records if r["prediction"] not in allowed]
    missing_provenance = [f"{r['case_id']}/{r['method']}" for r in records if not r.get("reasons") or not r.get("provenance")]

    swapped = []
    for case in cases:
        c = dict(case)
        c["ground_truth_label"] = "Applicable" if case["ground_truth_label"] == "Not Applicable" else "Not Applicable"
        swapped.append(c)
    swapped_ctx = build_context(mapping_info["mapping"], snapshot_info["snapshot"], advisory, observations, swapped)
    swapped_per_method, _swapped_records = predict_all(swapped_ctx, swapped)
    label_isolation = swapped_per_method == per_method

    report = {
        "mode": "check (pre-step-4 structural gate; no benchmark result emitted)",
        "generated_at_utc": now_utc(),
        "mapping_sha256": mapping_info["sha256"],
        "snapshot_manifest_sha256": snapshot_info["manifest_sha256"],
        "snapshot_cohorts": [{"dir": c["dir"], "manifest_sha256": c["manifest_sha256"],
                              "snapshot_date": c["snapshot_date"], "n_cves_loaded": c["n_cves_loaded"]}
                             for c in snapshot_info["cohorts"]],
        "n_cases": len(cases),
        "n_methods": len(methods_mod.METHODS),
        "n_records": len(records),
        "all_predictions_in_allowed_set": not bad,
        "invalid_predictions": bad,
        "label_isolation_preserved": label_isolation,
        "records_missing_reasons_or_provenance": missing_provenance,
        "benchmark_result_written": False,
        "metrics_computed": False,
        "metric_code_invoked": False,
        "predictions_computed": True,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "check-report.json").write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["load", "check", "benchmark", "fixture"])
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--run-benchmark", action="store_true", help="required for the real comparison run (step 4)")
    args = ap.parse_args(argv)

    if args.mode == "load":
        meta = mode_load(args.out or DEFAULT_OUT)
        print(json.dumps({k: meta[k] for k in ("mode", "mapping", "snapshot", "counts")}, indent=1, ensure_ascii=False))
        print("\nOK — frozen inputs verified; no predictions produced (step 4 owns that).")
        return 0
    if args.mode == "check":
        report = mode_check(args.out or (HERE / "output" / "check"))
        print(json.dumps(report, indent=1, ensure_ascii=False))
        return 0 if (report["all_predictions_in_allowed_set"] and report["label_isolation_preserved"]
                     and not report["records_missing_reasons_or_provenance"]) else 1
    if args.mode == "benchmark":
        if not args.run_benchmark:
            print("refusing to run the real benchmark without --run-benchmark (step 4 gate)", file=sys.stderr)
            return 2
        out = mode_benchmark(args.out or (HERE / "output" / "benchmark"))
        print(json.dumps(out["metrics"]["methods"], indent=1, ensure_ascii=False)[:4000])
        return 0
    if args.mode == "fixture":
        sys.path.insert(0, str(HERE / "fixture"))
        import run_fixture  # noqa: E402

        return run_fixture.main(args.out or (HERE / "fixture" / "output"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
