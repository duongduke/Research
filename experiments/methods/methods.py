"""methods.py — the five evaluation methods for RQ-C1 step 3.

Implements the frozen rules of `notes/fusion-design-2026-10-10.md` §3–§4 (D-026 +
R1/R2 amendment D-027) against the frozen collector/mapping
`notes/collector-mapping-30cve.md` (D-030 as amended through the 2026-10-17 top-up;
32 blocks, D-037 freeze pending) and the frozen snapshot cohorts
`data/public-snapshot/` (D-026, 2026-10-11) + `data/public-snapshot-2026-10-17/`
(D-035, 2 top-up CVE IDs).  Each `snapshot` entry carries `_cohort_dir`, so evidence
provenance points at the cohort that actually holds the artifact.

Methods
-------
cpe_only            E1 (cpe.json ranges, product-filtered) + E5
nvd_only            E1 (NVD `configurations` CPE, product-filtered) + E2 metadata + E5
advisory_only       E1 (normalised advisory range) + E3 + E4 + E5
http_version_only   E5 + reference range lookup table (CPE ranges), level 1 only
fusion              E1–E6, tiered, canonical B / P_i conclusion

Hard rules enforced in this module
----------------------------------
* **G7 runtime gate** — only `validation.status == "verified"` probes may produce
  True/False or an E5 value.  `pending` / `needs_control` -> Unknown, regardless of
  any recorded response.
* **Source isolation** — every method reads only its own source (see the docstring
  of each function).  `cpe_only` never reads `nvd.json`, `nvd_only` never reads
  `cpe.json` and never uses the CNA `affected[]`, `advisory_only` never borrows
  CPE/NVD ranges, `http_version_only` uses the CPE table *as a declared lookup*.
* **B / P_i separation** — `B` (build affected) is computed from
  product/version/range/patch; `P_i` is the all-of of `kind: precondition`
  conditions of impact path *i*.  A blocked path (Not Applicable branch b) does
  **not** require `B = True`.
* **E4 first** — a verified target↔patched-build linkage (`Context.patch_linkage`) is
  evaluated *before* the version/range tiers and establishes `B = False` (branch a) on
  its own, even when the version is hidden or a source has no range for the product.
* **Empty range is missing data, not a negative** — a source whose range list is empty
  after the product filter yields `Unknown`; `versioncmp.match_ranges(v, [])` returns
  `False`, so `fusion` guards the call (2026-10-15 review findings 2/3).
* **No ground truth** — no function here accepts a case label; the case view is
  asserted to be label-free (see `_assert_label_free`).

Every method returns a dict:
``{case_id, cve_id, method, prediction, reasons[], evidence{}, provenance{}}``
where ``prediction`` ∈ {"Applicable", "Not Applicable", "Unknown"}.
"""

from __future__ import annotations

import re

import versioncmp

APPLICABLE = "Applicable"
NOT_APPLICABLE = "Not Applicable"
UNKNOWN = "Unknown"

METHODS = ("cpe_only", "nvd_only", "advisory_only", "http_version_only", "fusion")

FORBIDDEN_CASE_KEYS = ("ground_truth_label", "label", "label_branch", "label_source")

IDENTITY_CONDITION_RE = re.compile(r"^p_(version_observed|product_)")
PATCH_CONDITION_RE = re.compile(r"(patched|backport|_fix)", re.I)


def _assert_label_free(case: dict) -> None:
    leaked = [k for k in FORBIDDEN_CASE_KEYS if k in case]
    if leaked:
        raise AssertionError(f"label isolation violated: case view carries {leaked}")


# --------------------------------------------------------------------------- #
# Context: read-only accessor over the frozen inputs.
# --------------------------------------------------------------------------- #
class Context:
    """Accessors over (mapping, snapshot, advisory_ranges, observations).

    ``snapshot`` = ``{cve_id: {"cpe": <cpe.json dict>, "nvd": <nvd.json dict>}}``
    ``observations`` = ``{case_id: {"observations": [...], "unobserved": [...]}}``
    """

    def __init__(self, mapping: dict, snapshot: dict, advisory_ranges: dict, observations: dict, cases_meta: dict):
        self.mapping = mapping
        self.snapshot = snapshot
        self.advisory_ranges = advisory_ranges
        self.observations = observations
        self.cases_meta = cases_meta

    # -- reference data ---------------------------------------------------- #
    def ref(self, cve_id: str) -> dict:
        return (self.mapping.get(cve_id) or {}).get("reference", {}) or {}

    def conditions(self, cve_id: str) -> dict:
        return self.ref(cve_id).get("conditions") or {}

    def paths(self, cve_id: str) -> list:
        return self.ref(cve_id).get("paths") or []

    def probes(self, cve_id: str) -> list:
        return ((self.mapping.get(cve_id) or {}).get("method", {}) or {}).get("probes") or []

    def decision_inputs(self, cve_id: str) -> list:
        return ((self.mapping.get(cve_id) or {}).get("method", {}) or {}).get("decision_inputs") or []

    # -- range sources ----------------------------------------------------- #
    def _cohort(self, cve_id: str) -> str:
        """Snapshot cohort root of ``cve_id`` (2026-10-11 or the 2026-10-17 top-up)."""
        return ((self.snapshot.get(cve_id) or {}).get("_cohort_dir")) or "data/public-snapshot"

    def _cpe_entries(self, cve_id: str) -> list:
        return ((self.snapshot.get(cve_id) or {}).get("cpe") or {}).get("cpe_match") or []

    def _nvd_entries(self, cve_id: str) -> list:
        """CPE match entries straight out of the NVD `configurations` tree."""
        nvd = (self.snapshot.get(cve_id) or {}).get("nvd") or {}
        out = []
        for vuln in nvd.get("vulnerabilities") or []:
            for config in vuln.get("cve", {}).get("configurations") or []:
                for node in config.get("nodes") or []:
                    for match in node.get("cpeMatch") or []:
                        if match.get("vulnerable"):
                            out.append(match)
        return out

    @staticmethod
    def _product_filter(entries: list, product_keys: list) -> list:
        """Keep only vulnerable CPE entries scoped to the case product (G-ruling B9)."""
        keep = []
        for e in entries:
            if e.get("vulnerable") is False:
                continue
            name = e.get("cpeName") or e.get("criteria") or ""
            parts = name.split(":")
            key = f"{parts[3]}:{parts[4]}" if len(parts) > 4 else ""
            if key in product_keys:
                keep.append(e)
        return keep

    def cpe_ranges(self, cve_id: str, product_keys: list) -> dict:
        entries = self._product_filter(self._cpe_entries(cve_id), product_keys)
        return {
            "source": "cpe",
            "artifact": f"{self._cohort(cve_id)}/{cve_id}/cpe.json",
            "entries": entries,
            "ranges": [versioncmp.normalise_cpe_entry(e) for e in entries],
        }

    def nvd_ranges(self, cve_id: str, product_keys: list) -> dict:
        entries = self._product_filter(self._nvd_entries(cve_id), product_keys)
        return {
            "source": "nvd_configurations",
            "artifact": f"{self._cohort(cve_id)}/{cve_id}/nvd.json",
            "entries": entries,
            "ranges": [versioncmp.normalise_cpe_entry(e) for e in entries],
        }

    def advisory_entry(self, cve_id: str) -> dict:
        return (self.advisory_ranges.get(cve_id) or {}) if self.advisory_ranges else {}

    def nvd_cna_affected(self, cve_id: str) -> list:
        """CNA `affected[]` statements — recorded as **provenance only**.

        The frozen rule set excludes this field from the NVD-only range source
        (D-028 R1): NVD-only uses `configurations` CPE only.
        """
        nvd = (self.snapshot.get(cve_id) or {}).get("nvd") or {}
        out = []
        for vuln in nvd.get("vulnerabilities") or []:
            for aff in vuln.get("cve", {}).get("affected") or []:
                out.append({"source": aff.get("source"), "affectedData": aff.get("affectedData")})
        return out

    def nvd_metadata(self, cve_id: str) -> dict:
        """E2 only: CVSS/CWE metadata (never changes an Applicable/Not conclusion)."""
        nvd = (self.snapshot.get(cve_id) or {}).get("nvd") or {}
        out = {"cvss": [], "cwe": []}
        for vuln in nvd.get("vulnerabilities") or []:
            cve = vuln.get("cve", {})
            for key, metrics in (cve.get("metrics") or {}).items():
                for m in metrics:
                    data = m.get("cvssData") or {}
                    out["cvss"].append({"source": m.get("source"), "type": m.get("type"), "metric": key, "base": data.get("baseScore"), "severity": data.get("baseSeverity")})
            for w in cve.get("weaknesses") or []:
                for d in w.get("description") or []:
                    out["cwe"].append({"source": w.get("source"), "value": d.get("value")})
        return out

    # -- observations ------------------------------------------------------ #
    def case_observations(self, case: dict) -> dict:
        return self.observations.get(case["case_id"]) or {"observations": [], "unobserved": []}

    def accepted_predicates(self, case: dict) -> dict:
        """condition_id -> {"value": "True"|"False"|"Unknown", "probe_id", "why"}.

        G7 gate: a predicate is only True/False when the probe that carries it is
        ``validation.status == verified``; otherwise Unknown (no True/False, no E5).
        """
        cve_id = case["cve_id"]
        probes = {p.get("id"): p for p in self.probes(cve_id)}
        out = {}
        for obs in self.case_observations(case)["observations"]:
            probe = probes.get(obs["probe_id"])
            if probe is None:
                continue
            cond = obs["condition_id"]
            status = (probe.get("validation") or {}).get("status")
            if status != "verified":
                out[cond] = {"value": UNKNOWN, "probe_id": obs["probe_id"], "why": f"G7 gate: probe status={status!r} is not verified"}
                continue
            value = obs.get("predicate_value")
            if value is None:
                out[cond] = {"value": UNKNOWN, "probe_id": obs["probe_id"], "why": "verified probe carries no decidable predicate value"}
            else:
                out[cond] = {"value": "True" if value else "False", "probe_id": obs["probe_id"], "why": obs.get("predicate_reason", "")}
        for obs in self.case_observations(case)["unobserved"]:
            cond = obs["condition_id"]
            status = obs.get("validation_status")
            out.setdefault(
                cond,
                {"value": UNKNOWN, "probe_id": obs["probe_id"], "why": f"G7 gate: probe status={status!r} -> Unknown (no accepted capture)"},
            )
        for cond in self.conditions(cve_id):
            out.setdefault(cond, {"value": UNKNOWN, "probe_id": None, "why": "no probe for this condition (observable=false or not evaluated)"})
        return out

    def e5(self, case: dict) -> dict:
        """E5: product/version inferred from accepted HTTP evidence only."""
        cve_id = case["cve_id"]
        identity_conds = {c for c in self.conditions(cve_id) if IDENTITY_CONDITION_RE.match(c)}
        observations = []
        for obs in self.case_observations(case)["observations"]:
            if obs["condition_id"] not in identity_conds:
                continue
            probe = next((p for p in self.probes(cve_id) if p.get("id") == obs["probe_id"]), None)
            status = ((probe or {}).get("validation") or {}).get("status")
            if status != "verified":
                continue
            observations.append(obs)
        tokens = [t.lower() for t in (case.get("identity_tokens") or [])]
        family = (case.get("identity_family") or "").lower()
        identified = False
        identity_text = None
        for obs in observations:
            text = (obs.get("identity_text") or "").lower()
            if not tokens:
                # no declared identity tokens for this case product -> cannot claim identification
                continue
            if not any(t in text for t in tokens):
                continue
            if family and not re.search(rf"(^|\D){re.escape(family)}(\.|\D|$)", text):
                continue
            identified = True
            identity_text = obs.get("identity_text")
            if obs.get("version"):
                return {
                    "identified": True,
                    "identity_text": identity_text,
                    "version": obs["version"],
                    "version_status": obs.get("version_status", "observed"),
                    "observations": observations,
                }
        version = None
        version_status = "not_observed"
        for obs in observations:
            if obs.get("version"):
                version = obs["version"]
                version_status = obs.get("version_status", "observed")
        if not observations:
            version_status = "no_capture"
        return {
            "identified": identified,
            "identity_text": identity_text,
            "version": version if version_status == "observed" else None,
            "version_status": version_status,
            "observations": observations,
        }

    def patch_linkage(self, case: dict) -> dict:
        """E4: accepted evidence that the *target* runs a patched build.

        Requires a build-kind patch condition with a verified probe whose value is
        True (a linked, verified patch signal).  A distro fix that is not linked to
        the observed target does **not** count (R2 / fusion-design §4 tier 3).
        """
        cve_id = case["cve_id"]
        conds = self.conditions(cve_id)
        preds = self.accepted_predicates(case)
        for cond_id, spec in conds.items():
            if (spec or {}).get("kind") != "build":
                continue
            if not PATCH_CONDITION_RE.search(cond_id):
                continue
            p = preds.get(cond_id)
            if p and p["value"] == "True":
                return {"linked": True, "condition": cond_id, "why": p["why"]}
        return {"linked": False, "why": "no accepted target<->patched-build linkage (E4)"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _pred(preds: dict, cond_id: str) -> dict:
    return preds.get(cond_id) or {"value": UNKNOWN, "probe_id": None, "why": "condition not present in mapping"}


def _result(case: dict, method: str, prediction: str, reasons: list, evidence: dict, provenance: dict) -> dict:
    return {
        "case_id": case["case_id"],
        "cve_id": case["cve_id"],
        "method": method,
        "prediction": prediction,
        "reasons": reasons,
        "evidence": evidence,
        "provenance": provenance,
    }


def _level1(case: dict, ctx: Context, source: str, product_keys: list, method: str) -> dict:
    """Shared level-1 (version ∈ affected range) decision for CPE-only/NVD-only."""
    _assert_label_free(case)
    cve_id = case["cve_id"]
    e5 = ctx.e5(case)
    prov = {"source": source, "cve": cve_id, "decision_inputs": ctx.decision_inputs(cve_id)}
    if source == "cpe":
        src = ctx.cpe_ranges(cve_id, product_keys)
    else:
        src = ctx.nvd_ranges(cve_id, product_keys)
        prov["e2_metadata"] = ctx.nvd_metadata(cve_id)
        prov["cna_affected_provenance_only"] = ctx.nvd_cna_affected(cve_id)
        prov["cna_affected_used_as_range"] = False
    prov["range_artifact"] = src["artifact"]
    prov["ranges"] = [dict(r) for r in src["ranges"]]
    evidence = {"e5": e5, "ranges": src["ranges"], "decisions": []}
    if not e5["identified"]:
        return _result(case, method, UNKNOWN, [f"E5: target product not identified from accepted HTTP evidence ({e5['version_status']})"], evidence, prov)
    if not src["ranges"]:
        return _result(case, method, UNKNOWN, [f"no {source} range record scoped to the case product {product_keys}"], evidence, prov)
    version = e5["version"]
    if version is None:
        return _result(case, method, UNKNOWN, [f"E5: version {e5['version_status']}; missing version is not 'outside the range'"], evidence, prov)
    ok, reasons = versioncmp.match_ranges(version, src["ranges"])
    evidence["decisions"] = reasons
    if ok is True:
        return _result(case, method, APPLICABLE, [f"observed {version} ∈ {source} affected range"], evidence, prov)
    if ok is False:
        return _result(case, method, NOT_APPLICABLE, [f"observed {version} ∉ {source} affected range"], evidence, prov)
    return _result(case, method, UNKNOWN, [f"observed {version} not comparable to {source} range: {reasons}"], evidence, prov)


# --------------------------------------------------------------------------- #
# 1. CPE-only
# --------------------------------------------------------------------------- #
def cpe_only(case: dict, ctx: Context) -> dict:
    """E1 (cpe.json only) + E5.  Never reads nvd.json or the advisory."""
    return _level1(case, ctx, "cpe", case.get("cpe_vendor_product") or case.get("product_key") or [], "cpe_only")


# --------------------------------------------------------------------------- #
# 2. NVD-only
# --------------------------------------------------------------------------- #
def nvd_only(case: dict, ctx: Context) -> dict:
    """E1 (NVD `configurations` CPE) + E2 (metadata only) + E5.

    The CNA `affected[]` field is *not* used as a range source (D-028 R1); it is
    recorded as provenance only.
    """
    return _level1(case, ctx, "nvd", case.get("cpe_vendor_product") or case.get("product_key") or [], "nvd_only")


# --------------------------------------------------------------------------- #
# 3. Advisory-only
# --------------------------------------------------------------------------- #
def advisory_only(case: dict, ctx: Context) -> dict:
    """E1 (normalised advisory range) + E3 + E4 + E5, in the §3.3 priority order."""
    _assert_label_free(case)
    cve_id = case["cve_id"]
    adv = ctx.advisory_entry(cve_id)
    e5 = ctx.e5(case)
    prov = {
        "source": "advisory",
        "cve": cve_id,
        "advisory_artifact": adv.get("artifact"),
        "range_artifact": adv.get("artifact"),
        "extraction_kind": adv.get("extraction_kind"),
        "ranges": adv.get("ranges"),
        "decision_inputs": ctx.decision_inputs(cve_id),
    }
    evidence = {"e5": e5, "advisory": {k: adv.get(k) for k in ("ranges", "extraction_kind", "null_reason", "scope_note", "quotes")}}

    # (1) E4 first: a linked patched-build conclusion outranks the missing-precondition branch.
    link = ctx.patch_linkage(case)
    if link["linked"]:
        return _result(
            case, "advisory_only", NOT_APPLICABLE,
            [f"E4: target linked to a patched build ({link['condition']}) — branch a"], evidence, prov,
        )

    # (2) no machine-readable range / product not matched
    if not adv or adv.get("ranges") in (None, []):
        return _result(
            case, "advisory_only", UNKNOWN,
            [f"advisory has no machine-readable affected range ({adv.get('null_reason') or 'not recorded'}) — missing data is not 'outside the range'"],
            evidence, prov,
        )
    if not e5["identified"]:
        return _result(case, "advisory_only", UNKNOWN, ["E5: target product not identified from accepted HTTP evidence"], evidence, prov)
    version = e5["version"]
    if version is None:
        return _result(case, "advisory_only", UNKNOWN, [f"E5: version {e5['version_status']}; advisory-only cannot place the target in/out of the range"], evidence, prov)

    ok, reasons = versioncmp.match_ranges(version, adv["ranges"])
    evidence["decisions"] = reasons

    # (3) outside the stated range -> branch a
    if ok is False:
        return _result(case, "advisory_only", NOT_APPLICABLE, [f"observed {version} ∉ advisory affected range"], evidence, prov)
    if ok is None:
        return _result(case, "advisory_only", UNKNOWN, [f"observed {version} not comparable to advisory range: {reasons}"], evidence, prov)

    # (4)/(5) inside the range: advisory knows the preconditions (E3) but has no E6
    preconds = sorted({c for p in ctx.paths(cve_id) for c in (p.get("all_of") or [])})
    if preconds:
        return _result(
            case, "advisory_only", UNKNOWN,
            [f"observed {version} ∈ advisory range, but the impact path(s) require preconditions {preconds} that advisory-only cannot observe (no E6)"],
            evidence, prov,
        )
    return _result(case, "advisory_only", APPLICABLE, [f"observed {version} ∈ advisory range and the advisory names no precondition in scope"], evidence, prov)


# --------------------------------------------------------------------------- #
# 4. HTTP version-string-only
# --------------------------------------------------------------------------- #
def http_version_only(case: dict, ctx: Context) -> dict:
    """E5 + a declared reference range lookup table.  Level 1 only (no E3/E4/E6)."""
    res = _level1(case, ctx, "cpe", case.get("cpe_vendor_product") or case.get("product_key") or [], "http_version_only")
    res["provenance"]["lookup_table"] = "reference CPE ranges (declared lookup, D-016)"
    res["provenance"]["note"] = "level-1 only: version string + range table; no patch/precondition/feature evidence"
    return res


# --------------------------------------------------------------------------- #
# 5. Fusion
# --------------------------------------------------------------------------- #
def fusion(case: dict, ctx: Context) -> dict:
    """Tiered fusion over E1–E6 with the canonical B / P_i conclusion (§4, §4.5)."""
    _assert_label_free(case)
    cve_id = case["cve_id"]
    preds = ctx.accepted_predicates(case)
    e5 = ctx.e5(case)
    adv = ctx.advisory_entry(cve_id)
    cpe = ctx.cpe_ranges(cve_id, case["cpe_vendor_product"])
    nvd = ctx.nvd_ranges(cve_id, case["cpe_vendor_product"])
    prov = {
        "cve": cve_id,
        "sources": {
            "e1_advisory": {"artifact": adv.get("artifact"), "ranges": adv.get("ranges"), "extraction_kind": adv.get("extraction_kind")},
            "e1_nvd": {"artifact": nvd["artifact"], "ranges": nvd["ranges"]},
            "e1_cpe": {"artifact": cpe["artifact"], "ranges": cpe["ranges"]},
        },
        "e2_metadata": ctx.nvd_metadata(cve_id),
        "decision_inputs": ctx.decision_inputs(cve_id),
    }
    evidence = {"e5": e5, "tier1_identity": {}, "tier2_range": {}, "tier3_patch": {}, "tier4_paths": []}

    # ---- Tier 1/2/3: B ---------------------------------------------------- #
    b_reasons = []
    product_identified = e5["identified"]
    version = e5["version"]
    B = UNKNOWN
    # Tier 3 (E4) is evaluated FIRST and independently of the version/range tiers:
    # a verified target<->patched-build linkage establishes B=False (branch a) even
    # when the version is hidden or a source range is missing (§3.3 rule (1), §4
    # tier 3; review finding 3).  `advisory_only` already does E4-first.
    link = ctx.patch_linkage(case)
    if link["linked"]:
        B = False
        b_reasons.append(f"tier 3 (E4): {link['why']}")
    else:
        b_reasons.append("tier 3 (E4): no accepted target<->patched-build linkage")
        if not product_identified:
            b_reasons.append("tier 1: target product not identified from accepted HTTP evidence")
        elif version is None:
            b_reasons.append(f"tier 1/2: version {e5['version_status']} — B undetermined (no version is not 'outside the range')")
        else:
            adv_ranges = adv.get("ranges") or []
            adv_verdict = None
            if adv_ranges:
                adv_verdict, why = versioncmp.match_ranges(version, adv_ranges)
                b_reasons.append(f"tier 2 advisory({adv.get('extraction_kind')}): {version} -> {adv_verdict} [{why}]")
            # An empty range list after the product filter means *no data for this
            # product*, not "outside the range" (review finding 2): match_ranges([])
            # returns False, which would fabricate a negative.  Empty -> None (Unknown).
            nvd_ranges = nvd["ranges"] or []
            cpe_ranges = cpe["ranges"] or []
            nvd_verdict, nvd_why = (versioncmp.match_ranges(version, nvd_ranges) if nvd_ranges
                                    else (None, "no NVD range scoped to the case product (missing data is not 'outside the range')"))
            cpe_verdict, cpe_why = (versioncmp.match_ranges(version, cpe_ranges) if cpe_ranges
                                    else (None, "no CPE range scoped to the case product (missing data is not 'outside the range')"))
            b_reasons.append(f"tier 2 nvd_configurations: {version} -> {nvd_verdict}")
            b_reasons.append(f"tier 2 cpe: {version} -> {cpe_verdict}")
            # precedence for the same assertion + same scope (advisory > NVD > CPE, D-019 §4.1)
            decidable = {k: v for k, v in (("advisory", adv_verdict), ("nvd", nvd_verdict), ("cpe", cpe_verdict)) if v is not None}
            if adv_verdict is not None:
                B, chosen_src = adv_verdict, "advisory"
            elif nvd_verdict is not None and cpe_verdict is not None and nvd_verdict != cpe_verdict:
                # same-tier conflict inside the NVD/CPE content (cpe.json is a derived
                # extraction of the same `configurations` tree) -> unresolved
                B, chosen_src = UNKNOWN, "nvd/cpe (same-tier conflict)"
            elif nvd_verdict is not None:
                B, chosen_src = nvd_verdict, "nvd_configurations"
            elif cpe_verdict is not None:
                B, chosen_src = cpe_verdict, "cpe"
            else:
                B, chosen_src = UNKNOWN, None
            if chosen_src:
                b_reasons.append(f"tier 2: B from {chosen_src} (precedence advisory > NVD > CPE for the same assertion+scope)")
            else:
                b_reasons.append("tier 2: no source yields a decidable verdict for the observed version -> B Unknown")
            if len(decidable) > 1 and len(set(decidable.values())) > 1:
                b_reasons.append(f"tier 2 note: source verdicts disagree {decidable}; precedence applied, disagreement reported")
            evidence["tier2_source_verdicts"] = {"advisory": adv_verdict, "nvd": nvd_verdict, "cpe": cpe_verdict, "chosen": chosen_src, "disagreement": len(set(decidable.values())) > 1}
    evidence["tier1_identity"] = {"identified": product_identified, "identity_text": e5.get("identity_text"), "version": version, "status": e5["version_status"]}
    evidence["tier2_range"] = {"B_from_range": B, "reasons": b_reasons}
    evidence["tier3_patch"] = link

    # ---- Tier 4: P_i ------------------------------------------------------ #
    paths = ctx.paths(cve_id)
    path_results = []
    for path in paths:
        cond_ids = path.get("all_of") or []
        values = []
        for c in cond_ids:
            p = _pred(preds, c)
            values.append({"condition": c, "value": p["value"], "why": p["why"], "kind": (ctx.conditions(cve_id).get(c) or {}).get("kind")})
        if any(v["value"] == "False" for v in values):
            p_i = "False"
        elif values and all(v["value"] == "True" for v in values):
            p_i = "True"
        elif not values:
            p_i = "True"  # empty conjunction: no observable precondition (e.g. nginx 23017)
        else:
            p_i = "Unknown"
        path_results.append({"path_id": path.get("id"), "scope_ref": path.get("scope_ref"), "P_i": p_i, "conditions": values})
    evidence["tier4_paths"] = path_results

    scope_determined = len(paths) > 0
    any_path_true = any(p["P_i"] == "True" for p in path_results)
    all_paths_false = bool(path_results) and all(p["P_i"] == "False" for p in path_results)
    undecided = [c["condition"] for p in path_results for c in p["conditions"] if c["value"] == UNKNOWN]

    if B is True and any_path_true:
        pred = APPLICABLE
        reasons = [f"B=True and path(s) {[p['path_id'] for p in path_results if p['P_i']=='True']} have all preconditions True"]
    elif B is False:
        pred = NOT_APPLICABLE
        reasons = [f"branch a: B=False ({b_reasons[-1] if b_reasons else 'build not affected'})"]
    elif product_identified and scope_determined and all_paths_false:
        pred = NOT_APPLICABLE
        reasons = ["branch b: target identified, path scope determined, every impact path has a precondition determined False (B not required)"]
    else:
        pred = UNKNOWN
        reasons = [
            f"B={B}; product_identified={product_identified}; scope_determined={scope_determined}; "
            f"P_i={[p['P_i'] for p in path_results]}"
            + (f"; undecided precondition(s) {undecided} (G7 gate / no accepted capture)" if undecided else "")
        ]

    return _result(
        case, "fusion", pred, reasons,
        {"B": B, "P_i": path_results, "b_reasons": b_reasons, "undecided_conditions": undecided, **evidence},
        prov,
    )


DISPATCH = {
    "cpe_only": cpe_only,
    "nvd_only": nvd_only,
    "advisory_only": advisory_only,
    "http_version_only": http_version_only,
    "fusion": fusion,
}


def run_method(method: str, case: dict, ctx: Context) -> dict:
    return DISPATCH[method](case, ctx)
