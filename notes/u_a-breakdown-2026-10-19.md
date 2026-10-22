# U_A breakdown — why fusion answers `Unknown` on 25 `Applicable` cases (V3 benchmark)

> Date: 2026-10-19. Author: engineer (read-only analysis).
> Question: of the V3 fusion abstentions, the **U_A** group (GT = `Applicable`,
> prediction = `Unknown`) is the only group that costs recall. This note classifies
> each U_A case by the *nature* of the blocking evidence, to separate what a V4
> "collect more precondition captures" pass can fix from what is a structural
> observability ceiling.
>
> **Read-only.** No mapping, snapshot, label, benchmark output or `context/` file was
> modified. The only artifact produced is this note. No lab / PoC was run.

## 1. Inputs and provenance

| Input | sha256 | Role |
|---|---|---|
| `experiments/methods/output/benchmark-v3/predictions.json` | `6d2908789bfcaca96045683373fd0c252ae5edd7babd3bc12aaaafcd41ce4a9b` | per-case fusion prediction + `B`, `P_i`, `undecided_conditions` |
| `experiments/methods/output/benchmark-v3/metrics.json` | `8070352303102028a9b21e82e02556e5b1f1aebb99a9b2f2bfbf236d8f2ef2c3` | confusion matrix / scores |
| `experiments/methods/output/benchmark-v3/run-metadata.json` | — | mapping hash, input hashes, counts |
| `experiments/methods/data/cases.json` | `2edb0e5a4ff03ac894e506ecf9634cb57d589e24be822f52fe619f045f2dd1ae` | labels + case identity |
| `experiments/methods/data/observations.json` | `f23917d381eab85a7b59e823250e69371453354e745a03c7b1db60ad67751bee` | accepted observations (G7) vs unobserved entries |
| `notes/collector-mapping-30cve.md` | `c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c` | `observable:`, `kind:`, `validation.status` |

Run context: `benchmark-v3`, generated `2026-10-17T15:45:40Z`, mapping hash matches
D-037, 32 CVE IDs / 69 cases, labels attached after prediction
(`labels_visible_to_methods: false`).

Enumeration (no rerun of the harness; join of the saved outputs):

```python
cases = {c["case_id"]: c for c in json.load(open(".../data/cases.json"))["cases"]}
recs  = json.load(open(".../output/benchmark-v3/predictions.json"))["per_case_records"]
UA = [r for r in recs if r["method"] == "fusion"
      and cases[r["case_id"]]["ground_truth_label"] == "Applicable"
      and r["prediction"] == "Unknown"]
# -> 25 cases (metrics.json: fusion U_A = 25, TP = 6, N_Applicable = 31)
```

The 25 cases are exactly the fusion `U_A` count in `metrics.json`, so the enumeration
is complete.

## 2. Metric context

| Quantity | Value |
|---|---|
| Applicable denominator (N) | 31 |
| fusion TP / FP / FN_def / U_A / U_N | 6 / 0 / 0 / **25** / 23 |
| recall | 6/31 = 0.1935 |
| precision | 1.0 |
| F1 | 0.3243 |

Every U_A is an *abstention*, not a wrong definite answer (`FN_def = 0`). The whole
recall gap is therefore "evidence missing at decision time", which is why classifying
the missing evidence is the right unit of analysis.

## 3. Classification legend

Blocker codes used in the table (each maps to a field in the frozen mapping, not to a
judgement about the CVE):

| Code | Meaning | Consequence |
|---|---|---|
| `P-pending` | precondition has a probe with `validation.status: pending` | a benign HTTP capture can decide it |
| `P-noobs` | precondition has `observable: false` (no probe) | **structural** under the frozen rules |
| `P-needs-control` | precondition has `validation.status: needs_control` (observable but only with a control state / role) | needs a control session, not a plain capture |
| `P-no-probe` | precondition is `observable: true` but the frozen mapping defines **no probe** for it | needs a mapping amendment + capture (not capture alone) |
| `B-pending` | B undetermined only because an identity/version probe is `pending` | capture can decide it |
| `B-version-hidden` | B undetermined because the minor/patch version is `observable: false` (hidden by the product) | **structural** (version hiding) |
| `B-no-identity-probe` | B undetermined and no identity probe is defined even though product identity is `observable: true` | mapping gap, but still blocked in this CVE by version hiding |

`fixable?`:

- **yes** — every blocker is `P-pending` / `B-pending` (capture + the mechanical
  promotion path is sufficient).
- **maybe** — additionally needs a probe definition for an `observable: true`
  condition that the frozen mapping never probed (`P-no-probe`) → mapping amendment.
- **no** — at least one `P-noobs` or `B-version-hidden` blocker → cannot become
  `Applicable` by collecting more benign HTTP under the frozen rules.

"Mechanical promotion path" = new capture artifact (both control states) → mapping
`validation.status` promotion (new mapping hash, D-030-style amendment) →
`VERIFIED_EXTRACTORS` entry in `build_inputs.py` → regenerate inputs → fixture/harness
re-run. A capture alone changes nothing at runtime (G7).

## 4. The 25 U_A cases

`B` and `P_i` are quoted from the fusion `evidence` block; condition ids from the frozen
mapping. `(p)` = probe pending, `(c)` = needs_control, `(–)` = `observable:false`, `(∅)` =
`observable:true` with no probe.

| case_id | CVE | blocking (B or P_i + condition ids) | class | fixable? |
|---|---|---|---|---|
| `CVE-2021-41773__weakened_249` | CVE-2021-41773 | `B=True` (2.4.49 observed); `P_i`: `p_diroots_require_all_granted` (–), `p_file_outside_docroot` (–) | `P-noobs` ×2 | **no** |
| `CVE-2019-6340__rest_on_869` | CVE-2019-6340 | `B=Unknown` (no identity probe; `p_core_version_lt_8610` –); `P_i`: `p_rest_module_on` (p), `p_link_field_fixture` (–), `p_auth_content_creation` (c) | `B-version-hidden` + `B-no-identity-probe` + `P-pending` + `P-noobs` + `P-needs-control` | **no** |
| `CVE-2019-6340__rest_off_jsonapi_on_869` | CVE-2019-6340 | same as above but `path_jsonapi`: `p_jsonapi_route_on` (p), `p_link_field_fixture` (–), `p_auth_content_creation` (c) | same | **no** |
| `CVE-2020-12625__1_4_3` | CVE-2020-12625 | `B=Unknown` (identity probe (p); `p_version_lt_144` –); `P_i`: `p_message_view_auth` (–), `p_browser_executes` (–) | `B-version-hidden` + `P-noobs` ×2 | **no** |
| `CVE-2014-3704__vuln` | CVE-2014-3704 | `B=Unknown` (Drupal 7 identified; `p_core_version_lt_732` –); `P_i`: `p_login_form_reachable` (p) | `B-version-hidden` + `P-pending` | **no** |
| `CVE-2015-3440__vuln` | CVE-2015-3440 | `B=True` (4.2-src); `P_i`: `p_comments_open_on_post` (p), `p_content_column_is_text_64k` (–) | `P-pending` + `P-noobs` | **no** |
| `CVE-2018-7600__vuln` | CVE-2018-7600 | `B=Unknown` (Drupal 8 identified; `p_core_version_in_affected_86` –); `P_i`: `p_user_register_ajax_wrapper` (p) | `B-version-hidden` + `P-pending` | **no** |
| `CVE-2018-7602__vuln` | CVE-2018-7602 | `B=Unknown` (identity probe (p); `p_core_version_lt_759` –); `P_i`: `p_authenticated_session` (p) | `B-version-hidden` + `B-pending` + `P-pending` | **no** |
| `CVE-2019-10692__vuln` | CVE-2019-10692 | `B=Unknown` (`p_version_observed` readme (p)); `P_i`: `p_markers_route_registered` (p) | `B-pending` + `P-pending` | **yes** |
| `CVE-2019-8942__vuln` | CVE-2019-8942 | `B=True` (5.0); `P_i`: `p_upload_capable_author` (c), `p_image_editor_and_self_fetch` (–) | `P-needs-control` + `P-noobs` | **no** |
| `CVE-2020-12640__config_on_vuln` | CVE-2020-12640 | `B=Unknown` (identity probe (p); `p_version_lt_144` –); `P_i`: `p_installer_public` (p), `p_attacker_writes_local_php` (–) | `B-version-hidden` + `P-pending` + `P-noobs` | **no** |
| `CVE-2020-12641__config_on_vuln` | CVE-2020-12641 | `B=Unknown` (identity probe (p); `p_version_lt_144` –); `P_i`: `p_installer_public` (p), `p_image_attachment_resize` (∅) | `B-version-hidden` + `P-pending` + `P-no-probe` | **no** |
| `CVE-2020-13671__config_on_vuln` | CVE-2020-13671 | `B=Unknown` (Drupal 8 identified; `p_core_version_lt_899` –); `P_i`: `p_unsafe_ext_file_field` (–), `p_upload_permission` (–) | `B-version-hidden` + `P-noobs` ×2 | **no** |
| `CVE-2020-25213__vuln` | CVE-2020-25213 | `B=Unknown` (readme (p)); `P_i`: `p_connector_reachable` (p), `p_upload_writable_no_block` (–) | `B-pending` + `P-pending` + `P-noobs` | **no** |
| `CVE-2021-24917__vuln` | CVE-2021-24917 | `B=Unknown` (readme (p)); `P_i`: `p_secret_login_configured` (p) | `B-pending` + `P-pending` | **yes** |
| `CVE-2021-29447__vuln` | CVE-2021-29447 | `B=True` (5.7); `P_i`: `p_php8_runtime=True`, `p_author_upload` (c), `p_oob_attacker_reachable` (–) | `P-needs-control` + `P-noobs` | **no** |
| `CVE-2021-42013__vuln` | CVE-2021-42013 | `B=True` (2.4.50); `P_i`: `p_diroots_require_all_granted` (–) | `P-noobs` | **no** |
| `CVE-2021-44026__vuln` | CVE-2021-44026 | `B=Unknown` (identity probe (p); `p_version_lt_1412` –); `P_i`: `p_auth_session` (–), `p_contacts_fixture` (–) | `B-version-hidden` + `P-noobs` ×2 | **no** |
| `CVE-2022-21661__vuln` | CVE-2022-21661 | `B=True` (5.8.2); `P_i`: `p_trigger_plugin_present=True`, `p_fixture_route_unauth` (p) | `P-pending` | **yes** |
| `CVE-2023-2745__vuln` | CVE-2023-2745 | `B=True` (6.2); `P_i`: `p_crafted_mo_present` (–) | `P-noobs` | **no** |
| `CVE-2023-28121__vuln` | CVE-2023-28121 | `B=Unknown` (readme (p)); `P_i`: `p_woocommerce_active` (∅), `p_known_admin_id` (p) | `B-pending` + `P-no-probe` + `P-pending` | **maybe** |
| `CVE-2023-32243__vuln` | CVE-2023-32243 | `B=Unknown` (readme (p)); `P_i`: `p_elementor_active` (∅), `p_eael_nonce_unauth` (p), `p_known_username` (p) | `B-pending` + `P-no-probe` + `P-pending` ×2 | **maybe** |
| `CVE-2023-5798__vuln` | CVE-2023-5798 | `B=Unknown` (`p_version_observed` –, **verified negative-observability probe**); `P_i`: `p_editor_role` (c; `observable:false`) | `B-version-hidden` + `P-needs-control` | **no** |
| `CVE-2024-28000__vuln` | CVE-2024-28000 | `B=Unknown` (readme (p)); `P_i`: `p_nopriv_async_handler` (p), `p_crawler_config_on` (–) | `B-pending` + `P-pending` + `P-noobs` | **no** |
| `CVE-2024-37383__vuln` | CVE-2024-37383 | `B=Unknown` (identity probe (p); `p_version_lt_157` –); `P_i`: `p_message_view_auth` (–), `p_victim_click` (–) | `B-version-hidden` + `P-noobs` ×2 | **no** |

## 5. Counts

### 5.1 Primary classes

| Class | Count | Cases |
|---|---|---|
| **(a) fully fixable by capture** (all blockers `pending`) | **3** | 10692, 24917, 21661 |
| **(b) partially fixable / uncertain** (needs a probe definition for an `observable:true` condition → mapping amendment, then capture) | **2** | 28121, 32243 |
| **(c) structural-only** (≥1 `observable:false` or version-hidden B) | **20** | the rest |
| total | 25 | |

`needs_control` appears in 5 cases (6340 ×2, 8942, 29447, 5798) but **never as the sole
blocker** — every one of those cases also has an `observable:false` precondition or a
version-hidden B. That is why the `maybe` bucket is only the two `P-no-probe` cases and
not the `needs_control` ones: a control session would still leave those 5 blocked.

### 5.2 Structure of the 20 structural cases

| Sub-class | Count | Cases |
|---|---|---|
| B blocked by hidden version (`p_core_version*`/`p_version_lt*` `observable:false`) | 12 | 6340 ×2, 12625, 3704, 7600, 7602, 12640, 12641, 13671, 44026, 5798, 37383 |
| B known or capture-fixable, but ≥1 necessary precondition is `observable:false` | 8 | 41773, 3440, 8942, 42013, 29447, 2745, 25213, 28000 |

Of the 12 version-hidden cases, **4 have no other structural blocker** (the hidden minor
version is the *only* reason they cannot be concluded): `CVE-2014-3704` (only
`p_login_form_reachable` pending otherwise), `CVE-2018-7600`, `CVE-2018-7602`,
`CVE-2020-12641` (config-on). These are the cases a *rule* change (family-level or
indirect build inference) would unlock — not an engineering/capture change.

The 8 precondition-blocked cases are blocked by facts with no benign HTTP channel under
the frozen rules: a server misconfiguration (`41773`, `42013` — `<Directory />` `Require
all granted`), a DB column type (`3440`), image-editor/self-fetch capability (`8942`), an
out-of-band attacker callback (`29447`), a planted `.mo` file (`2745`), upload-directory
writability (`25213`), and crawler/role-simulation config (`28000`). Six of these
(41773, 3440, 8942, 42013, 29447, 2745) have `B=True` already, so for those the *entire*
remaining gap is the precondition; the other two (25213, 28000) have a capturable B
(`readme.txt`) but still cannot conclude.

### 5.3 Product-family distribution

| Family | U_A | fixable/maybe | structural |
|---|---|---|---|
| WordPress (core + plugins) | 12 | **5** (10692, 24917, 21661, 28121, 32243) | 7 |
| Drupal | 6 | 0 | 6 |
| Roundcube | 5 | 0 | 5 |
| Apache httpd | 2 | 0 | 2 |

The capture gains are entirely WordPress-plugin/core evidence (readme `Stable tag`,
`/?rest_route=/`, a fixture AJAX route). Drupal and Roundcube contribute zero fixable
cases: their identity/version is the hidden part, exactly as the lab noted (Drupal's
`X-Generator` exposes family only; Roundcube `/CHANGELOG` is 403).

## 6. Maximum fusion recall

Best case, i.e. every (a) and (b) case turns into a TP and nothing else changes:

- TP: 6 → **11** (6 + 3 + 2)
- denominator unchanged: N_Applicable = 31
- recall: 11/31 = **0.3548** (from 0.1935)
- precision stays 1.0 (no new FP; the other 20 stay Unknown, not wrong)
- F1 (arithmetic projection, not a measurement): 2·11/(31+11) = **0.5238**

Conservative variant if the two (b) cases cannot get their dependency probes
(`p_woocommerce_active`, `p_elementor_active`), i.e. only the (a) captures land:

- TP 6 → 9; recall 9/31 = **0.2903**; F1 = 18/40 = **0.45**

So the honest envelope for a V4 that only *collects benign HTTP captures* is
**recall 0.29–0.35**, i.e. at most ~36% of Applicable cases and still ~65% of them
abstained. These TP ceilings are derived arithmetic from the saved confusion matrix; no
new run was made.

## 7. Notable cases and flags (for the researcher, not decisions)

1. **`CVE-2023-5798` is the only case where the structural nature is itself measured.**
   Its `probe_home_no_assistant_version` is `verified` as a *negative-observability*
   probe: the capture shows no `assistant` asset with `?ver=` in **both** 1.4.3 and 1.4.4.
   That is a methodological asset — "version not observable" is evidence, not an
   assumption — but it also means the case can never be concluded by the current E5 rule.
2. **`CVE-2019-6340` contains a mapping/scope inconsistency worth a ruling.** The
   mapping marks `p_link_field_fixture` `observable:false` with the note "only observable
   with permission to view the field list — outside the unauth access model", but this
   case's access model **is** authenticated (`auth(content-creation)`, D-015). Under an
   authenticated access model the fixture may be observable (e.g. field list / JSON:API
   field output). As frozen, the case is structural; a ruling could move 2 cases to
   `P-needs-control`/pending. Flagged, not changed.
3. **`CVE-2021-41773` (weakened) and `CVE-2021-42013` are the cleanest statement of the
   structural ceiling.** Both have `B=True` from a verified `Server` header, and the only
   blocker is the misconfiguration — which the frozen rules (G3: no bare 403/404 → False)
   deliberately refuse to infer from the exploit request. Two TP are lost to a rule
   choice, not to missing data.
4. **`CVE-2023-2745` and `CVE-2022-21661` are lab-constructed Applicables.** 2745
   requires a crafted `.mo` planted at a traversal path; 21661 requires the Ele Custom
   Skin fixture. For 21661 the fixture *asset* is verified (`?ver=3.1.3`), so only the
   unauth route probe is missing — the cheapest single win in the set. For 2745 the
   planted file is not observable at all.
5. **The three (a) cases are the only pure-capture wins, and they are all WordPress.**
   10692 and 24917 need the same `readme.txt` `Stable tag` capture that already produced
   TP for CVE-2023-3460 and CVE-2023-6553 — i.e. the evidence class is proven; these two
   are the lowest-risk V4 captures. 21661 needs one pending route probe.
6. **`P-no-probe` conditions are a distinct gap from `pending`.** `p_woocommerce_active`
   and `p_elementor_active` are declared `observable:true` in the mapping but have no
   probe; likewise `p_image_attachment_resize` (12641). These need a mapping amendment
   before any capture can matter, and there are 3 such conditions across 3 U_A cases
   (2 of which are in bucket (b)). They are not "collect more of the same".
7. **The 20 structural cases cannot be fixed by engineering.** Unlocking them requires
   relaxing the Applicable criterion or admitting a new evidence channel (e.g.
   exploit-derived config inference, family-level build inference, or authenticated
   fixture probing where the case's access model already allows it) — each is a
   methodology amendment and a new decision, not a V4 capture pass.
8. **Denominator caveat.** The 31 Applicable cases include config-on/fixture states that
   the lab itself constructed (e.g. 12640/12641/13671 config-on, 41773 weakened, 6340
   REST-on). Their GT `Applicable` is correct for the constructed deployment, but no
   benign external observer can certify the constructed state. Part of the 0.65
   abstention rate is therefore a property of the benchmark's case design, not only of
   the method. This should be stated when reporting recall, and it is a separate question
   from whether the method is right to abstain.
9. **Two `yes` cases carry an unused declared identity condition.** `CVE-2019-10692`
   (`p_plugin_slug_present`) and `CVE-2021-24917` (`p_plugin_whl_present`) declare a
   `kind: build` condition that is `observable:true` but has no probe; E5 only reads
   `p_version_observed` / `p_product_*`, and no impact path contains build conditions, so
   the decision is unaffected today. If a future ruling requires that declared identity
   condition to be verified, both become `P-no-probe` (3→1 in bucket (a), 2→4 in bucket
   (b)); max recall is unchanged (still 11) but the effort per case increases.

## 8. What this implies for a V4 capture pass (engineering view, not a decision)

Cheapest-first, with the expected effect on the U_A set:

| Priority | Capture | Cases unlocked | Effect |
|---|---|---|---|
| 1 | WP plugin `readme.txt` `Stable tag` (both vuln/fixed states) + extractor | 10692, 24917 | +2 TP (recall 8/31) |
| 2 | WP fixture AJAX route probe (`wp_ajax_nopriv_ecsload`) | 21661 | +1 TP (recall 9/31) |
| 3 | Dependency-presence probes (WooCommerce active, Elementor active) — mapping amendment first | 28121, 32243 | +2 TP (recall 11/31) |
| — | anything else in the U_A set | — | no change: blocked by `observable:false` or hidden version |

Steps 1–2 are pure capture + wiring; step 3 is a mapping amendment.

## 9. Limitations

- Classification is based on the **frozen mapping's** `observable:` flags and probe
  `validation.status`, not on an independent observability audit. If a flag is wrong
  (see flag 2 above), a case's class changes; this note does not re-litigate the flags.
- A `pending` probe that is collected may still evaluate **False** (e.g. readme blocked,
  REST route absent, registration disabled), in which case the path stays blocked and the
  case remains `Unknown`; the recall figures in §6 are therefore an upper bound.
- Cases are counted per deployment case, consistent with `cases.json`; CVE IDs are not a
  separate denominator here.
- No fusion rerun, no new observations, no label or mapping edit was performed.
