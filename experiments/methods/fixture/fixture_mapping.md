# Synthetic fixture mapping (step 3 phase C) — NOT part of the benchmark.

> Hand-built, fake CVE IDs (`CVE-9000-*`) exercising the rule set that the five
> methods implement.  Same schema as `notes/collector-mapping-30cve.md` (D-030), so
> the fixture runs through **the same** `methods.py` / `metrics.py` code path.
> Nothing here is a measurement or a claim about any real CVE.

## CVE-9000-0001 — inclusive/exclusive range boundaries

```yaml
CVE-9000-0001:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0001/cpe.json", field: "cpe_match[]", literal: "widget:web 2.0<=v<3.0"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0001/nvd.json", field: "configurations", literal: "widget:web 2.0<=v<3.0"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0001", literal: ">=2.0 <3.0"}
    conditions:
      p_version_observed: {description: "version token observable over HTTP (E5)", source_ref: "E5", observable: true, kind: build}
      p_plugins_enabled: {description: "plugin subsystem enabled (E6)", source_ref: "advisory", observable: true, kind: precondition}
    paths:
      - {id: path_plugin_abuse, all_of: [p_plugins_enabled], scope_ref: "fixture SA-9000-1"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "banner carries a version token", false_when: "banner carries no version token", ambiguity_when: "banner absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_below", "f_in", "f_end"], artifact_refs: ["fixture/artifacts/captures.txt"], note: "synthetic capture"}
      - id: probe_plugins
        request: {method: GET, path: "/plugins"}
        maps_to: p_plugins_enabled
        interpret: {true_when: "plugin list renders", false_when: "plugin subsystem explicitly disabled", ambiguity_when: "404", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_in", "f_off"], artifact_refs: ["fixture/artifacts/captures.txt"], note: "synthetic capture"}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0002 — exact-version CPE entry + product filtering

```yaml
CVE-9000-0002:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0002/cpe.json", field: "cpe_match[]", literal: "widget:web exact 1.4; decoy other:thing vulnerable=false"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0002/nvd.json", field: "configurations", literal: "widget:web exact 1.4"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0002", literal: "= 1.4"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_no_precondition: {description: "no precondition named by the advisory", source_ref: "advisory", observable: false, kind: precondition}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-2"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "banner carries a version token", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_exact", "f_decoy"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0003 — B / P_i separation, NA-b without B=True, G7 gate

```yaml
CVE-9000-0003:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0003/cpe.json", field: "cpe_match[]", literal: "widget:web 1.0<=v<2.0"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0003/nvd.json", field: "configurations", literal: "widget:web 1.0<=v<2.0"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0003", literal: ">=1.0 <2.0"}
    conditions:
      p_product_widget: {description: "target is Widget Web (family identity)", source_ref: "E5", observable: true, kind: build}
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_feature_on: {description: "vulnerable feature enabled (E6)", source_ref: "advisory", observable: true, kind: precondition}
      p_role_ok: {description: "caller role has the required permission (E3)", source_ref: "advisory", observable: false, kind: precondition}
    paths:
      - {id: path_feature, all_of: [p_feature_on, p_role_ok], scope_ref: "fixture SA-9000-3"}
  method:
    contract: {access_model: auth(author), max_requests_per_case: 20}
    probes:
      - id: probe_family
        request: {method: GET, path: "/"}
        maps_to: p_product_widget
        interpret: {true_when: "family banner present", false_when: "other product banner", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_blocked", "f_blocked_noversion"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_blocked", "f_ok"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_feature
        request: {method: GET, path: "/feature"}
        maps_to: p_feature_on
        interpret: {true_when: "feature form renders", false_when: "feature explicitly switched off (page renders a disabled banner)", ambiguity_when: "404", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_blocked", "f_ok"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_role
        request: {method: GET, path: "/feature"}
        maps_to: p_role_ok
        interpret: {true_when: "no safe true_when (role is not exposed by HTTP)", false_when: "no safe false_when", ambiguity_when: "always ambiguous for role", otherwise: Unknown}
        validation: {status: needs_control, control_state_ids: ["f_blocked", "f_ok"], artifact_refs: []}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E3, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0004 — precedence: advisory vs CPE/NVD disagreement

```yaml
CVE-9000-0004:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0004/cpe.json", field: "cpe_match[]", literal: "widget:web 1.0<=v<3.0"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0004/nvd.json", field: "configurations", literal: "widget:web 1.0<=v<3.0"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0004", literal: "<1.0 (< 1.0)"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_no_precondition: {description: "no precondition", source_ref: "advisory", observable: false, kind: precondition}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-4"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_precedence"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0005 — same-tier conflict (NVD vs CPE) with no advisory range

```yaml
CVE-9000-0005:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0005/cpe.json", field: "cpe_match[]", literal: "widget:web 1.0<=v<3.0"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0005/nvd.json", field: "configurations", literal: "widget:web <1.0"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0005", literal: "null (no machine-readable range)"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_no_precondition: {description: "no precondition", source_ref: "advisory", observable: false, kind: precondition}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-5"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_tier_conflict"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E1_nvd, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0006 — no range record for the product + E4 patch linkage

```yaml
CVE-9000-0006:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0006/cpe.json", field: "cpe_match[]", literal: "only other:thing (not the case product)"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0006/nvd.json", field: "configurations", literal: "only other:thing"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0006", literal: "null"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_build_patched_backport: {description: "target build carries the vendor patch (E4)", source_ref: "distro", observable: true, kind: build}
      p_no_precondition: {description: "no precondition", source_ref: "advisory", observable: false, kind: precondition}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-6"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_no_range"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_patch_link
        request: {method: GET, path: "/"}
        maps_to: p_build_patched_backport
        interpret: {true_when: "the served build is the patched revision of this deployment", false_when: "the served build is unpatched", ambiguity_when: "revision not exposed", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_patched"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E4, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0007 — empty impact path (no observable precondition)

```yaml
CVE-9000-0007:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0007/cpe.json", field: "cpe_match[]", literal: "widget:web 1.0<=v<2.0"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0007/nvd.json", field: "configurations", literal: "widget:web 1.0<=v<2.0"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0007", literal: ">=1.0 <2.0"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
    paths:
      - {id: path_no_precondition, all_of: [], scope_ref: "fixture SA-9000-7"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_empty_path"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0008 — G7 runtime gate (pending probe must stay Unknown)

```yaml
CVE-9000-0008:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0008/cpe.json", field: "cpe_match[]", literal: "widget:web 1.0<=v<2.0"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0008/nvd.json", field: "configurations", literal: "widget:web 1.0<=v<2.0"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0008", literal: ">=1.0 <2.0"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_feature_on: {description: "vulnerable feature enabled (E6) — probe not yet validated", source_ref: "advisory", observable: true, kind: precondition}
    paths:
      - {id: path_feature, all_of: [p_feature_on], scope_ref: "fixture SA-9000-8"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_pending"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_feature
        request: {method: GET, path: "/feature"}
        maps_to: p_feature_on
        interpret: {true_when: "feature form renders", false_when: "feature disabled banner", ambiguity_when: "404", otherwise: Unknown}
        validation: {status: pending, control_state_ids: ["f_pending"], artifact_refs: ["fixture/artifacts/captures.txt"], note: "only one polarity captured -> pending (G7)"}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E5, E6]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture"
```

## CVE-9000-0010 — empty range list after the product filter (missing data ≠ out of range)

```yaml
CVE-9000-0010:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0010/cpe.json", field: "cpe_match[]", literal: "only other:thing (not the case product)"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0010/nvd.json", field: "configurations", literal: "only other:thing"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0010", literal: "null (no machine-readable range)"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-10"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_empty_ranges"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E1_nvd, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture — regression for review finding 2 (empty range must be Unknown, not Not Applicable)"
```

## CVE-9000-0011 — E4 independence pair (version hidden + no range, with/without patch linkage)

```yaml
CVE-9000-0011:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0011/cpe.json", field: "cpe_match[]", literal: "only other:thing (not the case product)"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0011/nvd.json", field: "configurations", literal: "only other:thing"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0011", literal: "null (no machine-readable range)"}
    conditions:
      p_product_widget: {description: "target is Widget Web (family identity)", source_ref: "E5", observable: true, kind: build}
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
      p_build_patched_backport: {description: "target build carries the vendor patch (E4)", source_ref: "distro", observable: true, kind: build}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-11"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_family
        request: {method: GET, path: "/"}
        maps_to: p_product_widget
        interpret: {true_when: "family banner present", false_when: "other product banner", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_e4_linked", "f_e4_unlinked"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "hidden by the deployment", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_blocked"], artifact_refs: ["fixture/artifacts/captures.txt"]}
      - id: probe_patch_link
        request: {method: GET, path: "/"}
        maps_to: p_build_patched_backport
        interpret: {true_when: "the served build is the patched revision of this deployment", false_when: "the served build is unpatched", ambiguity_when: "revision not exposed", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_e4_linked"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E4, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture — regression for review finding 3 (E4 must establish B=False without a version/range)"
```

## CVE-9000-0012 — advisory per-branch union (patched mid-branch release is out of range)

```yaml
CVE-9000-0012:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0012/cpe.json", field: "cpe_match[]", literal: "only other:thing (not the case product)"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0012/nvd.json", field: "configurations", literal: "only other:thing"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0012", literal: "per-branch union 4.8.0–4.8.2 / 4.9.0–4.9.1 / 5.5.0–5.5.2 / 5.6.0–5.6.2"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-12"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_branch_vuln", "f_branch_patched"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_advisory, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture — regression for review finding 4a (per-branch patched list, no single span)"
```

## CVE-9000-0013 — partial-scope advisory line (out-of-line = Unknown, not Not Applicable)

```yaml
CVE-9000-0013:
  reference:
    ranges_by_source:
      cpe: {artifact: "fixture/snapshot/CVE-9000-0013/cpe.json", field: "cpe_match[]", literal: "widget:web v<4.1.38"}
      nvd: {artifact: "fixture/snapshot/CVE-9000-0013/nvd.json", field: "configurations", literal: "widget:web v<4.1.38"}
      advisory: {artifact: "fixture/advisory_ranges.json", field: "CVE-9000-0013", literal: "line 6.2 only (fixed 6.2.1); older lines affected per 'since 4.1' with no stated fixed version -> out_of_scope: unknown"}
    conditions:
      p_version_observed: {description: "version token observable (E5)", source_ref: "E5", observable: true, kind: build}
    paths:
      - {id: path_plain, all_of: [], scope_ref: "fixture SA-9000-13"}
  method:
    contract: {access_model: unauth, max_requests_per_case: 20}
    probes:
      - id: probe_version
        request: {method: GET, path: "/"}
        maps_to: p_version_observed
        interpret: {true_when: "version token present", false_when: "no token", ambiguity_when: "absent", otherwise: Unknown}
        validation: {status: verified, control_state_ids: ["f_out_of_line", "f_in_line", "f_line_patched"], artifact_refs: ["fixture/artifacts/captures.txt"]}
    decision_inputs: [E1_cpe, E1_nvd, E1_advisory, E5]
  development_use:
    used_for_rule_development: false
    used_for_signal_development: false
    reason_ref: "fixture — regression for the CVE-2023-2745 partial-scope encoding (a non-6.2 line is Unknown for the advisory, and fusion must still resolve it from NVD/CPE)"
```
