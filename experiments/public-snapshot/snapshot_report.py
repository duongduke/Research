#!/usr/bin/env python3
"""
Factual data-quality report over a public-data snapshot (RQ-C1, D-026/D-027 R4).

Reads manifest.json + each cpe.json and prints neutral, mechanical facts:
- CPE match-entry counts and how many carry an explicit version range,
- whether the NVD record has any `configurations` at all,
- advisory HTTP status / redirect / content-type / byte size,
- duplicate advisory URLs and duplicate CPE criteria (redundancy observations).

No interpretation of affectedness is produced. Usage:
    python3 snapshot_report.py [--dir data/public-snapshot] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DIR = HERE.parent.parent / "data" / "public-snapshot"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    m = json.loads((args.dir / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    adv_counter = Counter()
    for cve, rec in sorted(m["artifacts"].items()):
        cpe_path = args.dir / cve / "cpe.json"
        n_entries = n_ranged = n_vuln = 0
        has_cfg = False
        if cpe_path.exists():
            cpe = json.loads(cpe_path.read_text(encoding="utf-8"))
            has_cfg = bool(cpe.get("configurations_raw"))
            for e in cpe["cpe_match"]:
                n_entries += 1
                if e.get("vulnerable"):
                    n_vuln += 1
                if any(k in e for k in ("versionStartIncluding", "versionStartExcluding",
                                        "versionEndIncluding", "versionEndExcluding")):
                    n_ranged += 1
        nvd = rec["files"].get("nvd", {})
        adv = rec["files"].get("advisory", {})
        if adv.get("declared_url"):
            adv_counter[adv["declared_url"]] += 1
        rows.append({
            "cve_id": cve,
            "nvd_status": nvd.get("http_status"),
            "nvd_bytes": nvd.get("bytes"),
            "has_configurations": has_cfg,
            "cpe_entries": n_entries,
            "cpe_vulnerable_entries": n_vuln,
            "cpe_entries_with_version_range": n_ranged,
            "advisory_status": adv.get("http_status"),
            "advisory_redirected": adv.get("redirected"),
            "advisory_content_type": adv.get("content_type"),
            "advisory_bytes": adv.get("bytes"),
            "failures": [f["reason"] for f in rec["failures"]],
        })

    print(f"# Snapshot data-quality report — {m['snapshot_date']}")
    print(f"\nCVEs: {len(rows)}; complete: {m['summary']['n_complete_nvd_cpe_advisory']}; "
          f"partial/failed: {m['summary']['n_partial_or_failed']}\n")
    print("| CVE | nvd | cfg? | cpe entries (vuln / ranged) | advisory | failures |")
    print("|---|---|---|---|---|---|")
    for r in rows:
        cpe_col = f"{r['cpe_entries']} ({r['cpe_vulnerable_entries']} / " \
                  f"{r['cpe_entries_with_version_range']})"
        adv = f"{r['advisory_status']}"
        if r["advisory_redirected"]:
            adv += " (redirect)"
        print(f"| {r['cve_id']} | {r['nvd_status']} | "
              f"{'yes' if r['has_configurations'] else 'NO'} | {cpe_col} | {adv} | "
              f"{'; '.join(r['failures'])} |")

    print("\n## Shared advisory URLs (redundancy observation)")
    for url, n in adv_counter.most_common():
        if n > 1:
            print(f"- {n}x {url}")

    no_cfg = [r["cve_id"] for r in rows if not r["has_configurations"]]
    zero = [r["cve_id"] for r in rows if r["cpe_entries"] == 0]
    print(f"\n- NVD records without any `configurations`: {no_cfg or 'none'}")
    print(f"- CVEs with zero CPE match criteria: {zero or 'none'}")

    if args.json:
        args.json.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        print(f"\n(wrote {args.json})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
