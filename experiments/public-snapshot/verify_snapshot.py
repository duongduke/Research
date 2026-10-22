#!/usr/bin/env python3
"""
Verify a public-data snapshot against its manifest (RQ-C1, D-026/D-027 R4).

Re-walks manifest.json, re-computes the sha256 of every artifact on disk and
reports mismatches, missing files and extra files. Exit code 0 = manifest and
files agree.

Usage:
    python3 verify_snapshot.py [--dir data/public-snapshot]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_DIR = HERE.parent.parent / "data" / "public-snapshot"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    args = ap.parse_args()

    manifest_path = args.dir / "manifest.json"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} not found", file=sys.stderr)
        return 2
    m = json.loads(manifest_path.read_text(encoding="utf-8"))

    checked = mismatched = missing = 0
    expected_files: set[Path] = {(args.dir / "manifest.json").resolve()}
    problems: list[str] = []

    def resolve(p: str) -> Path:
        q = Path(p)
        return (q if q.is_absolute() else args.dir / q).resolve()

    for cve, rec in sorted(m["artifacts"].items()):
        for kind, f in rec["files"].items():
            if not f.get("path"):
                pass
            else:
                p = resolve(f["path"])
                expected_files.add(p)
                checked += 1
                if not p.exists():
                    missing += 1
                    problems.append(f"MISSING {cve}/{kind}: {f['path']}")
                else:
                    actual = sha256_file(p)
                    if actual != f.get("sha256"):
                        mismatched += 1
                        problems.append(
                            f"HASH MISMATCH {cve}/{kind}: manifest={f.get('sha256')} "
                            f"actual={actual}")
            # failed-response audit bodies are hashed too
            if f.get("error_body"):
                p = resolve(f["error_body"])
                expected_files.add(p)
                checked += 1
                if not p.exists():
                    missing += 1
                    problems.append(f"MISSING {cve}/{kind} error_body: {f['error_body']}")
                else:
                    actual = sha256_file(p)
                    if actual != f.get("error_body_sha256"):
                        mismatched += 1
                        problems.append(
                            f"HASH MISMATCH {cve}/{kind} error_body: "
                            f"manifest={f.get('error_body_sha256')} actual={actual}")

    # extra files (excluding aux error bodies recorded in the manifest by name)
    error_bodies = {resolve(f["error_body"])
                    for rec in m["artifacts"].values()
                    for f in rec["files"].values() if f.get("error_body")}
    doc_files = {"manifest.md", "quality-report.md", "README.md"}
    extras = []
    for p in sorted(args.dir.rglob("*")):
        if p.is_dir() or p.name in doc_files:
            continue
        rp = p.resolve()
        if rp in expected_files or rp in error_bodies:
            continue
        if p.name in ("nvd.error.txt", "advisory-primary.error.txt",
                      "advisory-fallback.error.txt") or p.name.endswith(".error.txt"):
            continue
        extras.append(p)

    print(f"artifacts checked : {checked}")
    print(f"hash mismatches   : {mismatched}")
    print(f"missing files     : {missing}")
    print(f"unlisted files    : {len(extras)}")
    for p in extras:
        print(f"  unlisted: {p.relative_to(args.dir)}")
    for line in problems:
        print(f"  {line}")
    if not problems and not extras:
        print("\nOK — snapshot matches manifest.json")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
