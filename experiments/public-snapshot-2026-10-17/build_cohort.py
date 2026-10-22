#!/usr/bin/env python3
"""
RQ-C1 public-data snapshot — TOP-UP cohort 2026-10-17 (D-035 §5).

Builds a self-contained, hash-verifiable snapshot cohort for the 2 CVE IDs added
by D-035, from the step-1 evidence already persisted in
`experiments/topup-2026-10-17/sources/` (fetched 2026-10-17), producing:

    <out>/<CVE-ID>/nvd.json                  verbatim NVD 2.0 API response
    <out>/<CVE-ID>/cpe.json                  derived extraction of configurations/cpeMatch
    <out>/<CVE-ID>/advisory.<ext>            primary advisory (when HTTP 200)
    <out>/<CVE-ID>/advisory-fallback.<ext>   documented fallback (only when the primary is blocked)
    <out>/<CVE-ID>/advisory-primary.error.txt  failed-primary response body (audit only)
    <out>/manifest.json, <out>/manifest.md

Design rules (identical to the frozen 2026-10-11 cohort, D-026):
- raw bytes are copied verbatim; the sha256 in the manifest is over the saved bytes;
- `path` values are relative to the snapshot directory (portable, re-verifiable with
  `experiments/public-snapshot/verify_snapshot.py --dir <out>`);
- the CPE extraction is imported from `experiments/public-snapshot/fetch_public_snapshot.py`
  so BOTH cohorts use byte-identical extraction semantics;
- failures are recorded with a reason and never repaired/fabricated.

Difference from the frozen cohort fetch script: this build does **NOT** re-fetch from
the network.  Every artifact was already fetched on 2026-10-17 (step 1) and is
persisted locally; the manifest records the step-1 fetch timestamp per artifact and
marks the file `fetch_mode: inherited_from_step1`.  Re-fetching was rejected on
purpose: it would create data drift inside the same dated cohort and could not
reproduce the step-1 bytes.

Usage
-----
    python3 build_cohort.py                 # write data/public-snapshot-2026-10-17
    python3 build_cohort.py --out /tmp/x    # write elsewhere
    python3 build_cohort.py --check         # build to a temp dir, diff hashes, exit
Requires: python3 (no third-party network calls).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
WS = HERE.parent.parent
DEFAULT_OUT = WS / "data" / "public-snapshot-2026-10-17"
SOURCES = HERE / "sources.json"

COHORT = "2026-10-17"

CONTENT_TYPE_EXT = {
    "text/html": ".html",
    "application/json": ".json",
    "text/plain": ".txt",
    "application/xml": ".xml",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sniff_content_type(body: bytes) -> str:
    """Best-effort content type of the SAVED bytes (step-1 response headers were not persisted)."""
    head = body[:512].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<html" in head[:200]:
        return "text/html"
    if head.startswith(b"{") or head.startswith(b"["):
        return "application/json"
    if head.startswith(b"<?xml"):
        return "application/xml"
    return "application/octet-stream"


def import_extract_cpe():
    """Reuse the frozen cohort's CPE extractor (identical semantics across cohorts)."""
    sys.path.insert(0, str(WS / "experiments" / "public-snapshot"))
    import fetch_public_snapshot as fps  # noqa: WPS433 (deliberate cross-script import)

    return fps.extract_cpe


def read_and_check(local_source: str, sha_expected: str, bytes_expected: int | None,
                   label: str) -> tuple[bytes, Path]:
    path = WS / local_source
    if not path.exists():
        raise SystemExit(f"ERROR: missing step-1 artifact for {label}: {path}")
    data = path.read_bytes()
    got = sha256_bytes(data)
    if got != sha_expected:
        raise SystemExit(
            f"ERROR: {label}: sha256 mismatch against the step-1 record\n"
            f"  file            : {path}\n  expected (step1): {sha_expected}\n  actual          : {got}")
    if bytes_expected is not None and len(data) != bytes_expected:
        raise SystemExit(
            f"ERROR: {label}: byte size mismatch (expected {bytes_expected}, got {len(data)})")
    return data, path


def write_file(path: Path, data: bytes, base: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "path": str(path.relative_to(base)),
        "bytes": len(data),
        "sha256": sha256_bytes(data),
    }


def build(out_dir: Path, sources: dict, preserve_from: Path | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "cohort": COHORT,
        "snapshot_date": COHORT,
        "snapshot_date_source": "D-035 §5 (the 2 top-up CVEs form a separate snapshot cohort with the actual fetch date)",
        "separate_from": "data/public-snapshot/ (frozen 30-CVE cohort, 2026-10-11, D-026)",
        "manifest_generated_at_utc": utcnow(),
        "generator": "experiments/public-snapshot-2026-10-17/build_cohort.py",
        "sources_config": "experiments/public-snapshot-2026-10-17/sources.json",
        "nvd_api": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "nvd_rate_limit_note": "no API key; ~5 requests / 30 s. No NVD call was made by this build — all NVD bytes are inherited from the step-1 fetch of 2026-10-17.",
        "new_fetches_this_run": 0,
        "fetch_mode": "inherited_from_step1",
        "n_benchmark_cves": len(sources["cves"]),
        "artifacts": {},
        "failures": [],
    }
    failures: list[dict] = []

    for entry in sources["cves"]:
        cve = entry["cve_id"]
        cdir = out_dir / cve
        cdir.mkdir(parents=True, exist_ok=True)
        rec: dict = {
            "cve_id": cve,
            "product": entry.get("product"),
            "advisory_declared_url": (entry.get("advisory") or {}).get("url"),
            "advisory_url_provenance": (entry.get("advisory") or {}).get("provenance"),
            "files": {},
            "failures": [],
        }

        def add_failure(source, url, status, reason):
            item = {"source": source, "url": url, "http_status": status, "reason": reason}
            rec["failures"].append(item)
            failures.append({"cve_id": cve, **item})

        # ---- 1. NVD record (verbatim copy) --------------------------------
        n = entry["nvd"]
        data, src = read_and_check(n["local_source"], n["sha256_expected"],
                                   n.get("bytes_expected"), f"{cve}/nvd")
        try:
            record = json.loads(data)
            api_keys = {"resultsPerPage", "startIndex", "totalResults", "format", "vulnerabilities"}
            if not api_keys.issubset(record):
                raise ValueError(f"not an NVD 2.0 API envelope (keys: {sorted(record)})")
            got_id = record["vulnerabilities"][0]["cve"]["id"]
            if got_id != cve:
                raise ValueError(f"response is for {got_id}, expected {cve}")
        except Exception as exc:  # structural verification only, no repair
            raise SystemExit(f"ERROR: {cve}: NVD artifact failed structural check: {exc}")
        nvd_path = cdir / "nvd.json"
        rec["files"]["nvd"] = {
            "url": n["url"],
            "final_url": n["url"],
            "http_status": n["http_status"],
            "fetched_at_utc": n["fetched_at_utc"],
            "fetched_at_basis": n["fetched_at_basis"],
            "fetch_mode": "inherited_from_step1",
            "inherited_from": n["local_source"],
            "provenance": n["provenance"],
            "content_type": "application/json",
            "content_type_basis": "NVD 2.0 API contract + sniffed body ('{'); step-1 response headers were not persisted",
            "redirected": None,
            **write_file(nvd_path, data, out_dir),
        }

        # ---- 2. CPE extraction (derived) ----------------------------------
        cpe = extract_cpe(cve, record)
        cpe_path = cdir / "cpe.json"
        # Byte-stable rebuilds: the extraction is deterministic except for its timestamp,
        # so a rebuild reuses the FIRST extraction timestamp instead of churning the hash.
        extracted_at = utcnow()
        for prior in ([cpe_path] if cpe_path.exists() else []) + (
                [preserve_from / cve / "cpe.json"] if preserve_from else []):
            try:
                got = json.loads(prior.read_text(encoding="utf-8")).get("extracted_at_utc")
                if got:
                    extracted_at = got
                    break
            except Exception:
                continue
        cpe["extracted_at_utc"] = extracted_at
        cpe_path.write_text(json.dumps(cpe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        cb = cpe_path.read_bytes()
        rec["files"]["cpe"] = {
            "url": n["url"],
            "derived_from": "nvd.json",
            "fetched_at_utc": cpe["extracted_at_utc"],  # extraction time, NOT a fetch
            "fetched_at_basis": "derived locally from the saved nvd.json; timestamp preserved across rebuilds",
            "extracted_at_utc": cpe["extracted_at_utc"],
            "http_status": None,
            "n_cpe_match_entries": cpe["n_cpe_match_entries"],
            **write_file(cpe_path, cb, out_dir),
        }
        if cpe["n_cpe_match_entries"] == 0:
            add_failure("cpe", n["url"], 200,
                        "NVD record contains no CPE configurations/cpeMatch")

        # ---- 3. Advisory (primary + documented fallback) ------------------
        adv = entry.get("advisory")
        if adv:
            data, src = read_and_check(adv["local_source"], adv["sha256_expected"],
                                       adv.get("bytes_expected"), f"{cve}/advisory")
            ctype = sniff_content_type(data)
            meta = {
                "role": "primary",
                "declared_url": adv["url"],
                "provenance": adv["provenance"],
                "final_url": adv["url"],
                "http_status": adv["http_status"],
                "fetched_at_utc": adv["fetched_at_utc"],
                "fetched_at_basis": adv.get("fetched_at_basis"),
                "fetch_mode": "inherited_from_step1",
                "inherited_from": adv["local_source"],
                "content_type": ctype,
                "content_type_basis": "sniffed from saved bytes; step-1 response headers were not persisted",
                "redirected": None,
            }
            if adv["http_status"] == 200 and data:
                ext = CONTENT_TYPE_EXT.get(ctype, ".bin")
                rec["files"]["advisory"] = {
                    **meta, **write_file(cdir / f"advisory{ext}", data, out_dir)}
            else:
                reason = f"primary advisory HTTP {adv['http_status']}"
                meta["note"] = reason
                err_path = cdir / "advisory-primary.error.txt"
                eb = write_file(err_path, data, out_dir)
                meta.update({
                    "error_body": eb["path"],
                    "error_body_bytes": eb["bytes"],
                    "error_body_sha256": eb["sha256"],
                    "note": reason + " — body persisted as the failed-primary audit record, NOT as an advisory source",
                })
                rec["files"]["advisory"] = meta
                add_failure("advisory", adv["url"], adv["http_status"], reason)

        fb = entry.get("advisory_fallback")
        if fb:
            data, src = read_and_check(fb["local_source"], fb["sha256_expected"],
                                       fb.get("bytes_expected"), f"{cve}/advisory_fallback")
            ctype = sniff_content_type(data)
            ext = CONTENT_TYPE_EXT.get(ctype, ".bin")
            rec["files"]["advisory_fallback"] = {
                "role": "fallback",
                "declared_url": fb["url"],
                "provenance": fb["provenance"],
                "final_url": fb["url"],
                "http_status": fb["http_status"],
                "fetched_at_utc": fb["fetched_at_utc"],
                "fetched_at_basis": fb.get("fetched_at_basis"),
                "fetch_mode": "inherited_from_step1",
                "inherited_from": fb["local_source"],
                "content_type": ctype,
                "content_type_basis": "sniffed from saved bytes; step-1 response headers were not persisted",
                "redirected": None,
                "note": "fallback used because the primary advisory was bot-blocked; see failures",
                **write_file(cdir / f"advisory-fallback{ext}", data, out_dir),
            }

        for b in entry.get("blocked") or []:
            if b.get("persisted_as"):
                continue  # already recorded above as the primary error body
            reason = b["reason"] if "0-byte" in b["reason"] else b["reason"] + " (0-byte body, nothing persisted)"
            add_failure(b["source"], b["url"], b["http_status"], reason)

        manifest["artifacts"][cve] = rec

    manifest["failures"] = failures
    manifest["summary"] = summarize(manifest["artifacts"])
    manifest["manifest_generated_at_utc"] = utcnow()
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def summarize(arts: dict) -> dict:
    def ok(f):
        return bool(f) and f.get("http_status") in (200, None) and f.get("bytes", 0) > 0

    complete, nvd, cpe, prim, fb, part = [], 0, 0, 0, 0, []
    for cve, rec in arts.items():
        f = rec["files"]
        o_nvd, o_cpe = ok(f.get("nvd")), ok(f.get("cpe"))
        o_p, o_f = ok(f.get("advisory")), ok(f.get("advisory_fallback"))
        nvd += o_nvd
        cpe += o_cpe
        prim += o_p
        fb += o_f
        if o_nvd and o_cpe and (o_p or o_f):
            complete.append(cve)
        elif not (o_nvd and o_cpe and o_p):
            part.append(cve)
    return {
        "n_cves": len(arts),
        "n_complete_nvd_cpe_advisory": len(complete),
        "complete": complete,
        "n_partial_or_failed": len(part),
        "partial_or_failed": part,
        "n_unique_cves_with_nvd": nvd,
        "n_unique_cves_with_cpe": cpe,
        "n_unique_cves_with_primary_advisory": prim,
        "n_unique_cves_with_fallback_advisory": fb,
    }


def write_manifest_md(path: Path, m: dict) -> None:
    s = m["summary"]
    lines = [
        "# Public-data snapshot manifest — RQ-C1 TOP-UP cohort 2026-10-17",
        "",
        "> **Separate cohort.** These 2 CVE IDs were added by D-035 *after* the 2026-10-11",
        "> snapshot was frozen (D-026). Nothing here is backdated into `data/public-snapshot/`,",
        "> and the 30-CVE manifest/hashes are unchanged.",
        "",
        f"- Cohort / fetch date: **{m['snapshot_date']}** ({m['snapshot_date_source']})",
        f"- Manifest generated: `{m['manifest_generated_at_utc']}`",
        f"- Generator: `{m['generator']}` (sources: `{m['sources_config']}`)",
        f"- NVD API: `{m['nvd_api']}` — {m['nvd_rate_limit_note']}",
        f"- Benchmark CVEs in cohort: {m['n_benchmark_cves']} "
        f"(new network fetches this run: {m['new_fetches_this_run']})",
        "",
        "## Summary",
        "",
        f"- Complete (NVD + CPE + advisory-or-fallback): **{s['n_complete_nvd_cpe_advisory']}/{s['n_cves']}**",
        f"- With NVD record: {s['n_unique_cves_with_nvd']}",
        f"- With CPE extraction: {s['n_unique_cves_with_cpe']}",
        f"- With primary advisory (HTTP 200): {s['n_unique_cves_with_primary_advisory']}",
        f"- Using a documented fallback advisory: {s['n_unique_cves_with_fallback_advisory']}",
        f"- Partial/failed: {s['n_partial_or_failed']} "
        f"({', '.join(s['partial_or_failed']) or 'none'})",
        "",
        "## Per-CVE artifacts",
        "",
        "| CVE | nvd.json sha256 | CPE entries | advisory | advisory sha256 | failures |",
        "|---|---|---|---|---|---|",
    ]
    for cve, rec in sorted(m["artifacts"].items()):
        f = rec["files"]
        nvd, cpe, adv, fb = (f.get("nvd", {}), f.get("cpe", {}), f.get("advisory", {}),
                             f.get("advisory_fallback", {}))
        adv_name = Path(adv["path"]).name if adv.get("path") else (
            f"[HTTP {adv.get('http_status')}, error body only]" if adv else "—")
        adv_sha = adv.get("sha256") or ""
        if fb.get("path"):
            adv_name += " + " + Path(fb["path"]).name
            adv_sha = fb.get("sha256") or adv_sha
        fails = "; ".join(f"{x['source']}: {x['reason']}" for x in rec["failures"]) or ""
        lines.append(
            f"| {cve} | `{(nvd.get('sha256') or '')[:16]}…` | {cpe.get('n_cpe_match_entries', '')} | "
            f"{adv_name} | `{adv_sha[:16]}…` | {fails} |")
    lines += ["", "## Failure detail", ""]
    if not m["failures"]:
        lines.append("None recorded.")
    else:
        for x in m["failures"]:
            lines.append(f"- **{x['cve_id']}** / {x['source']}: {x['reason']} "
                         f"(`{x['url']}`, HTTP {x.get('http_status')})")
    lines += [
        "",
        "## Notes",
        "",
        "- Raw bytes are copied verbatim from the step-1 evidence "
        "(`experiments/topup-2026-10-17/sources/`, fetched 2026-10-17); the sha256 is",
        "  computed over the saved file and re-checkable with "
        "`experiments/public-snapshot/verify_snapshot.py --dir data/public-snapshot-2026-10-17`.",
        "- `fetched_at_utc` is the **actual fetch time of the bytes** — for every artifact here it is",
        "  inherited from the step-1 fetch (mtime, UTC), and `fetch_mode: inherited_from_step1` says so.",
        "  This build made no network request: re-fetching would create drift inside the same dated cohort.",
        "- `nvd.json` is the unmodified NVD 2.0 API response (structural check: API envelope keys + `cve.id`).",
        "  `cpe.json` is the extraction of the `configurations`/`cpeMatch` nodes, produced by the **same**",
        "  extractor as the 2026-10-11 cohort (imported from `experiments/public-snapshot/fetch_public_snapshot.py`).",
        "- `advisory-fallback.*` is used only when the primary advisory URL is bot-blocked;",
        "  `advisory-primary.error.txt` keeps the failed response body for audit. Both are recorded above.",
        "- Step-1 response headers were not persisted; `content_type` here is derived from the saved bytes",
        "  (`content_type_basis`), not from a recorded header.",
        "- Raw artifacts only: **no labels, no mapping decisions and no interpretation** live in this directory.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true",
                    help="build into a temp dir and compare hashes with an existing --out")
    args = ap.parse_args()

    global extract_cpe
    extract_cpe = import_extract_cpe()

    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    if args.check:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td) / "cohort"
            m = build(tmp, sources, preserve_from=args.out)
            write_manifest_md(tmp / "manifest.md", m)
            old = json.loads((args.out / "manifest.json").read_text(encoding="utf-8"))
            diffs = []
            for cve in sorted(set(m["artifacts"]) | set(old["artifacts"])):
                a = m["artifacts"].get(cve, {}).get("files", {})
                b = old["artifacts"].get(cve, {}).get("files", {})
                for kind in sorted(set(a) | set(b)):
                    if (a.get(kind) or {}).get("sha256") != (b.get(kind) or {}).get("sha256"):
                        diffs.append(f"{cve}/{kind}: {a.get(kind, {}).get('sha256')} != "
                                     f"{b.get(kind, {}).get('sha256')}")
            print(f"checked CVEs: {len(m['artifacts'])}; sha256 differences: {len(diffs)}")
            for d in diffs:
                print("  " + d)
            return 0 if not diffs else 1

    manifest = build(args.out, sources)
    write_manifest_md(args.out / "manifest.md", manifest)
    s = manifest["summary"]
    print(f"cohort: {args.out}")
    print(f"complete: {s['n_complete_nvd_cpe_advisory']}/{s['n_cves']}; "
          f"primary advisory: {s['n_unique_cves_with_primary_advisory']}; "
          f"fallback: {s['n_unique_cves_with_fallback_advisory']}; "
          f"partial/failed: {s['n_partial_or_failed']}")
    print(f"manifest: {args.out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
