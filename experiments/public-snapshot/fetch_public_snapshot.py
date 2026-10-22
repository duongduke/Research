#!/usr/bin/env python3
"""
RQ-C1 public-data snapshot fetcher (research decision D-026 / D-027 R4).

Fetches, for each CVE in the frozen 30-CVE benchmark:
  1. the NVD 2.0 CVE record            -> <CVE-ID>/nvd.json
  2. the CPE match criteria extracted
     from that record's configurations -> <CVE-ID>/cpe.json
  3. the vendor/NVD advisory URL       -> <CVE-ID>/advisory.<ext>
     (a documented fallback advisory  -> <CVE-ID>/advisory-fallback.<ext>
      is used ONLY when the recorded URL is bot-blocked/unavailable)

and writes a verifiable manifest (manifest.json + manifest.md) containing, per
artifact, the source URL, the ACTUAL fetch timestamp (ISO 8601 UTC), the HTTP
status, the byte size and the sha256 of the bytes exactly as saved.

Design notes
------------
- Raw bytes are written verbatim; nothing is re-encoded or normalised.
- Paths in the manifest are relative to the snapshot directory (portable,
  independently verifiable with verify_snapshot.py).
- The NVD API is rate limited: without an API key ~5 requests / 30 s. We sleep
  `--nvd-sleep` (default 7 s) between NVD requests and back off on 403/429/5xx.
- Failures are recorded in the manifest with a reason; no content is fabricated.
  A failed response body (e.g. a bot-challenge page) is kept as
  `advisory-primary.error.txt` for audit, never as `advisory.<ext>`.
- Timestamps are the wall-clock UTC time at which the response was received.

Usage
-----
    python3 fetch_public_snapshot.py                  # fetch all 30
    python3 fetch_public_snapshot.py --only CVE-2021-41773
    python3 fetch_public_snapshot.py --merge --only CVE-2024-10924
    python3 fetch_public_snapshot.py --no-advisory    # NVD/CPE only

Requires: python3, requests (no NVD API key needed).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent.parent / "data" / "public-snapshot"
SOURCES = HERE / "sources.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

UA = (
    "RQ-C1-public-snapshot/1.0 (academic graduation project; "
    "CVE applicability benchmark; contact: workspace owner)"
)

ADVISORY_TIMEOUT = 45
NVD_TIMEOUT = 45

CONTENT_TYPE_EXT = {
    "text/html": ".html",
    "application/xhtml+xml": ".html",
    "application/json": ".json",
    "text/json": ".json",
    "text/plain": ".txt",
    "text/xml": ".xml",
    "application/xml": ".xml",
}


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def guess_ext(url: str, content_type: str | None, body: bytes = b"") -> str:
    base = (content_type or "").split(";")[0].strip().lower()
    if base in CONTENT_TYPE_EXT:
        return CONTENT_TYPE_EXT[base]
    # sniff the body when the server sent no/unknown content type
    head = body[:512].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<html" in head[:200]:
        return ".html"
    if head.startswith(b"{") or head.startswith(b"["):
        return ".json"
    tail = url.split("?")[0].split("#")[0].rsplit("/", 1)[-1]
    for ext in (".html", ".htm", ".json", ".txt", ".xml", ".md", ".pdf"):
        if tail.lower().endswith(ext):
            return ext
    return ".txt" if base.startswith("text/") else ".bin"


def nvd_url(cve_id: str) -> str:
    return f"{NVD_API}?cveId={cve_id}"


def fetch_nvd(cve_id: str, retries: int = 3) -> tuple[int, bytes, str, dict]:
    """Return (http_status, body_bytes, final_url, headers). Retries on 403/429/5xx."""
    url = nvd_url(cve_id)
    last_status, last_body, last_url, last_headers = 0, b"", url, {}
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers={"User-Agent": UA, "Accept": "application/json"},
                                timeout=NVD_TIMEOUT)
            last_status, last_body, last_url, last_headers = (
                resp.status_code, resp.content, resp.url, dict(resp.headers))
            if resp.status_code == 200:
                return last_status, last_body, last_url, last_headers
            if resp.status_code in (403, 429) or resp.status_code >= 500:
                time.sleep(20 * attempt)  # rate limited / transient
                continue
            return last_status, last_body, last_url, last_headers
        except requests.RequestException as exc:
            last_status, last_body, last_headers = -1, str(exc).encode(), {"error": str(exc)}
            time.sleep(5 * attempt)
    return last_status, last_body, last_url, last_headers


def extract_cpe(cve_id: str, record: dict) -> dict:
    """Extract CPE match criteria (names + version ranges) from an NVD record."""
    cve = record["vulnerabilities"][0]["cve"]
    configurations = cve.get("configurations") or []
    affected = cve.get("affected") or []
    flat: list[dict] = []

    def walk_nodes(nodes, cfg_id, cfg_operator, cfg_negate, path):
        for ni, node in enumerate(nodes):
            node_path = f"{path}.n{ni}"
            for m in node.get("cpeMatch", []):
                entry = {
                    "cpeName": m.get("criteria"),
                    "matchCriteriaId": m.get("matchCriteriaId"),
                    "vulnerable": m.get("vulnerable"),
                }
                for k in ("versionStartIncluding", "versionStartExcluding",
                          "versionEndIncluding", "versionEndExcluding"):
                    if m.get(k) is not None:
                        entry[k] = m[k]
                entry["_context"] = {
                    "configuration_id": cfg_id,
                    "configuration_operator": cfg_operator,
                    "configuration_negate": cfg_negate,
                    "node_path": node_path,
                    "node_operator": node.get("operator"),
                    "node_negate": node.get("negate"),
                }
                flat.append(entry)
            if "nodes" in node:
                walk_nodes(node["nodes"], cfg_id, cfg_operator, cfg_negate, node_path)

    for ci, cfg in enumerate(configurations):
        walk_nodes(cfg.get("nodes", []), cfg.get("id"), cfg.get("operator"),
                   cfg.get("negate"), f"c{ci}")

    return {
        "cve_id": cve_id,
        "extracted_at_utc": utcnow(),
        "source": nvd_url(cve_id),
        "nvd_record_timestamp": record.get("timestamp"),
        "vuln_status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "n_cpe_match_entries": len(flat),
        "cpe_match": flat,
        "configurations_raw": configurations,
        "affected_raw": affected,
    }


def fetch_url(url: str, retries: int = 2) -> tuple[int, bytes, str, dict]:
    last_status, last_body, last_url, last_headers = 0, b"", url, {}
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(
                url,
                headers={
                    "User-Agent": UA,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=ADVISORY_TIMEOUT,
                allow_redirects=True,
            )
            return resp.status_code, resp.content, resp.url, dict(resp.headers)
        except requests.RequestException as exc:
            last_status, last_body = -1, str(exc).encode()
            last_url, last_headers = url, {"error": str(exc)}
            if attempt < retries:
                time.sleep(5 * attempt)
    return last_status, last_body, last_url, last_headers


def write_artifact(path: Path, data: bytes, base: Path) -> dict:
    path.write_bytes(data)
    return {"path": str(path.relative_to(base)), "bytes": len(data),
            "sha256": sha256_bytes(data)}


# --------------------------------------------------------------------------- #
# manifest helpers
# --------------------------------------------------------------------------- #

def new_manifest(n_benchmark: int, nvd_sleep: float) -> dict:
    return {
        "snapshot_date": "2026-10-11",
        "snapshot_date_source": "D-026 (freeze public CVE data snapshot at 2026-10-11)",
        "manifest_generated_at_utc": utcnow(),
        "generator": "experiments/public-snapshot/fetch_public_snapshot.py",
        "sources_config": "experiments/public-snapshot/sources.json",
        "nvd_api": NVD_API,
        "nvd_rate_limit_note": "no API key; ~5 requests / 30 s (sleep=%.1fs between NVD calls)"
                               % nvd_sleep,
        "n_benchmark_cves": n_benchmark,
        "artifacts": {},
        "failures": [],
    }


def relativize(manifest: dict, base: Path) -> None:
    """Rewrite any absolute artifact path (older runs) as relative-to-snapshot."""
    for rec in manifest.get("artifacts", {}).values():
        for f in rec.get("files", {}).values():
            p = f.get("path")
            if p:
                try:
                    f["path"] = str(Path(p).resolve().relative_to(base.resolve()))
                except ValueError:
                    pass


def file_ok(f: dict | None) -> bool:
    return bool(f) and f.get("http_status") in (200, None) and f.get("bytes", 0) > 0


def recompute_summary(manifest: dict) -> None:
    arts = manifest["artifacts"]
    complete, nvd_ok, cpe_ok, adv_primary, adv_fallback, failures = [], 0, 0, 0, 0, []
    for cve, rec in arts.items():
        files = rec["files"]
        ok_nvd, ok_cpe = file_ok(files.get("nvd")), file_ok(files.get("cpe"))
        ok_prim = file_ok(files.get("advisory"))
        ok_fb = file_ok(files.get("advisory_fallback"))
        nvd_ok += ok_nvd
        cpe_ok += ok_cpe
        adv_primary += ok_prim
        adv_fallback += ok_fb
        if ok_nvd and ok_cpe and (ok_prim or ok_fb):
            complete.append(cve)
        elif not (ok_nvd and ok_cpe and ok_prim):
            failures.append(cve)
    manifest["summary"] = {
        "n_cves": len(arts),
        "n_complete_nvd_cpe_advisory": len(complete),
        "complete": complete,
        "n_partial_or_failed": len(failures),
        "partial_or_failed": failures,
        "n_unique_cves_with_nvd": nvd_ok,
        "n_unique_cves_with_cpe": cpe_ok,
        "n_unique_cves_with_primary_advisory": adv_primary,
        "n_unique_cves_with_fallback_advisory": adv_fallback,
    }


# --------------------------------------------------------------------------- #

def fetch_one(cve: str, entry: dict, out_dir: Path, args) -> dict:
    cdir = out_dir / cve
    cdir.mkdir(parents=True, exist_ok=True)
    rec: dict = {
        "cve_id": cve,
        "advisory_declared_url": entry.get("advisory_url"),
        "advisory_url_provenance": entry.get("provenance"),
        "files": {},
        "failures": [],
    }
    fails: list[dict] = []

    def add_failure(source, url, status, reason):
        item = {"source": source, "url": url, "http_status": status, "reason": reason}
        rec["failures"].append(item)
        fails.append({"cve_id": cve, **item})

    # ---- 1. NVD record -----------------------------------------------------
    nvd_path = cdir / "nvd.json"
    if args.skip_existing and nvd_path.exists() and nvd_path.stat().st_size > 0:
        data = nvd_path.read_bytes()
        rec["files"]["nvd"] = {
            "url": nvd_url(cve), "http_status": None, "fetched_at_utc": None,
            "note": "kept from previous run (--skip-existing)",
            **write_artifact(nvd_path, data, out_dir),
        }
        record = json.loads(data)
    else:
        status, body, final_url, headers = fetch_nvd(cve)
        meta = {"url": nvd_url(cve), "final_url": final_url, "http_status": status,
                "fetched_at_utc": utcnow(), "content_type": headers.get("Content-Type")}
        if status != 200:
            add_failure("nvd", nvd_url(cve), status, f"NVD HTTP {status}")
            meta["note"] = f"NVD HTTP {status}"
            (cdir / "nvd.error.txt").write_bytes(body)
            rec["files"]["nvd"] = {**meta, "bytes": len(body),
                                   "sha256": sha256_bytes(body)}
            record = None
        else:
            rec["files"]["nvd"] = {**meta, **write_artifact(nvd_path, body, out_dir)}
            record = json.loads(body)

    # ---- 2. CPE extraction -------------------------------------------------
    if record is not None:
        cpe_path = cdir / "cpe.json"
        try:
            cpe = extract_cpe(cve, record)
            cpe_path.write_text(json.dumps(cpe, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8")
            cb = cpe_path.read_bytes()
            rec["files"]["cpe"] = {
                "url": nvd_url(cve), "derived_from": "nvd.json",
                "fetched_at_utc": utcnow(), "http_status": None,
                "n_cpe_match_entries": cpe["n_cpe_match_entries"],
                **write_artifact(cpe_path, cb, out_dir),
            }
            if cpe["n_cpe_match_entries"] == 0:
                add_failure("cpe", nvd_url(cve), 200,
                            "NVD record contains no CPE configurations/cpeMatch "
                            "(no CPE match criteria available for this CVE)")
        except Exception as exc:
            add_failure("cpe", nvd_url(cve), None, f"CPE extraction failed: {exc}")

    # ---- 3. Advisory (primary, then documented fallback) -------------------
    kept = set()
    if not args.no_advisory:
        pinned = cdir / "advisory-primary.error.txt"
        for candidate in ("primary", "fallback"):
            if candidate == "primary":
                url = entry.get("advisory_url")
                role = "primary"
                prov = entry.get("provenance")
            else:
                url = entry.get("fallback_advisory_url")
                role = "fallback"
                prov = entry.get("fallback_provenance")
            if not url:
                continue
            status, body, final_url, headers = fetch_url(url)
            ext = guess_ext(final_url, headers.get("Content-Type"), body)
            meta = {"role": role, "declared_url": url, "provenance": prov,
                    "final_url": final_url, "http_status": status,
                    "fetched_at_utc": utcnow(),
                    "content_type": headers.get("Content-Type"),
                    "redirected": final_url.rstrip("/") != url.rstrip("/")}
            if status == 200 and body:
                name = "advisory" if role == "primary" else "advisory-fallback"
                path = cdir / f"{name}{ext}"
                rec["files"]["advisory" if role == "primary" else "advisory_fallback"] = {
                    **meta, **write_artifact(path, body, out_dir)}
                kept.add(path.name)
            else:
                reason = f"{role} advisory HTTP {status}" + (
                    f" ({headers.get('error')})" if headers.get("error") else "")
                if headers.get("error"):
                    reason = f"{role} advisory request failed: {headers['error']}"
                meta["note"] = reason
                if body:
                    err_path = cdir / f"advisory-{role}.error.txt"
                    err_path.write_bytes(body)
                    kept.add(err_path.name)
                    meta["error_body"] = str(err_path.relative_to(out_dir))
                    meta["error_body_bytes"] = len(body)
                    meta["error_body_sha256"] = sha256_bytes(body)
                rec["files"]["advisory" if role == "primary" else "advisory_fallback"] = meta
                add_failure("advisory" if role == "primary" else "advisory_fallback",
                            url, status, reason)
            if role == "primary" and rec["files"].get("advisory") \
                    and file_ok(rec["files"]["advisory"]):
                break  # primary succeeded; no fallback needed
        # drop stale advisory* files from earlier runs not part of this run
        for p in cdir.glob("advisory*"):
            if p.name not in kept:
                p.unlink()
    return rec, fails


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--only", action="append", default=None,
                    help="fetch only this CVE ID (repeatable)")
    ap.add_argument("--merge", action="store_true",
                    help="update an existing manifest.json instead of replacing it")
    ap.add_argument("--skip-existing", action="store_true",
                    help="reuse an existing nvd.json instead of re-fetching")
    ap.add_argument("--no-advisory", action="store_true")
    ap.add_argument("--nvd-sleep", type=float, default=7.0,
                    help="seconds between NVD API requests (default 7; no-key limit ~5/30s)")
    args = ap.parse_args()

    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    all_entries = sources["cves"]
    entries = all_entries
    if args.only:
        wanted = set(args.only)
        entries = [e for e in all_entries if e["cve_id"] in wanted]
        missing = wanted - {e["cve_id"] for e in entries}
        if missing:
            print(f"ERROR: not in sources.json: {sorted(missing)}", file=sys.stderr)
            return 2

    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    existing_path = out_dir / "manifest.json"
    if args.merge and existing_path.exists():
        manifest = json.loads(existing_path.read_text(encoding="utf-8"))
        manifest["manifest_generated_at_utc"] = utcnow()
        print(f"merging into existing manifest ({len(manifest['artifacts'])} CVEs)")
    else:
        manifest = new_manifest(len(all_entries), args.nvd_sleep)

    manifest["n_fetched_this_run"] = len(entries)

    for i, entry in enumerate(entries, 1):
        cve = entry["cve_id"]
        print(f"[{i}/{len(entries)}] {cve}", flush=True)
        rec, fails = fetch_one(cve, entry, out_dir, args)
        manifest["artifacts"][cve] = rec
        # drop this CVE's stale failures, then append the fresh ones
        manifest["failures"] = [f for f in manifest.get("failures", [])
                                if f.get("cve_id") != cve]
        manifest["failures"].extend(fails)
        if i < len(entries):
            time.sleep(args.nvd_sleep)

    relativize(manifest, out_dir)
    recompute_summary(manifest)
    manifest["manifest_generated_at_utc"] = utcnow()  # set at write time, >= all fetch times
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_manifest_md(out_dir / "manifest.md", manifest)

    s = manifest["summary"]
    print(f"\nDONE: {s['n_complete_nvd_cpe_advisory']}/{s['n_cves']} complete; "
          f"primary-advisory OK: {s['n_unique_cves_with_primary_advisory']}; "
          f"fallback used: {s['n_unique_cves_with_fallback_advisory']}; "
          f"partial/failed: {s['n_partial_or_failed']} -> {s['partial_or_failed'] or 'none'}")
    print(f"manifest: {out_dir / 'manifest.json'}")
    return 0 if not s["partial_or_failed"] else 1


def write_manifest_md(path: Path, m: dict) -> None:
    s = m["summary"]
    lines = [
        "# Public-data snapshot manifest — RQ-C1 30-CVE benchmark",
        "",
        f"- Snapshot date: **{m['snapshot_date']}** ({m['snapshot_date_source']})",
        f"- Manifest generated: `{m['manifest_generated_at_utc']}`",
        f"- Generator: `{m['generator']}` (sources: `{m['sources_config']}`)",
        f"- NVD API: `{m['nvd_api']}` — {m['nvd_rate_limit_note']}",
        f"- Benchmark CVEs: {m['n_benchmark_cves']} (fetched in last run: {m['n_fetched_this_run']})",
        "",
        "## Summary",
        "",
        f"- Complete (NVD + CPE + advisory): **{s['n_complete_nvd_cpe_advisory']}/{s['n_cves']}**",
        f"- With NVD record: {s['n_unique_cves_with_nvd']}",
        f"- With CPE extraction: {s['n_unique_cves_with_cpe']}",
        f"- With primary (notes-recorded) advisory: {s['n_unique_cves_with_primary_advisory']}",
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
        nvd = rec["files"].get("nvd", {})
        cpe = rec["files"].get("cpe", {})
        adv = rec["files"].get("advisory", {})
        fbk = rec["files"].get("advisory_fallback", {})
        n_entries = cpe.get("n_cpe_match_entries")
        n_entries = "" if n_entries is None else str(n_entries)
        adv_name = Path(adv["path"]).name if adv.get("path") else (
            f"[HTTP {adv.get('http_status')}, no body]" if adv else "—")
        adv_sha = adv.get("sha256") or ""
        if file_ok(fbk):
            adv_name += " + " + Path(fbk["path"]).name
            adv_sha = fbk.get("sha256") or adv_sha
        fails = "; ".join(f"{f['source']}: {f['reason']}" for f in rec["failures"]) or ""
        lines.append(
            f"| {cve} | `{(nvd.get('sha256') or '')[:16]}…` | {n_entries} | "
            f"{adv_name} | `{adv_sha[:16]}…` | {fails} |")
    lines += ["", "## Failure detail", ""]
    if not m["failures"]:
        lines.append("None recorded.")
    else:
        for f in m["failures"]:
            lines.append(f"- **{f['cve_id']}** / {f['source']}: {f['reason']} "
                         f"(`{f['url']}`, HTTP {f.get('http_status')})")
    lines += [
        "",
        "## Notes",
        "",
        "- Raw bytes are written verbatim; `sha256` is computed over the saved file and the",
        "  `path` values are relative to this snapshot directory.",
        "- `fetched_at_utc` is the wall-clock UTC time the response was received, per artifact.",
        "- `nvd.json` is the unmodified NVD 2.0 API response; `cpe.json` is the extraction of the",
        "  configurations/`cpeMatch` nodes (CPE names + version ranges) from that response.",
        "- `advisory-fallback.*` is used only when the notes-recorded advisory URL is",
        "  bot-blocked/unavailable; `advisory-primary.error.txt` keeps the failed response body",
        "  for audit. Both cases are recorded in the failure list above.",
        "- An advisory saved with HTTP 200 may still be an anti-bot page; check `http_status`,",
        "  `final_url`, `bytes` and the file content before use.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
