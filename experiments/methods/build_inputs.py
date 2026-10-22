#!/usr/bin/env python3
"""build_inputs.py — Phase A data preparation for RQ-C1 step 3.

Builds the three engineer-produced method inputs from **frozen** artifacts only:

* ``data/cases.json``             (M2) case list + ground-truth labels (used only
  after prediction, in the metric step)
* ``data/observations.json``      (M1) accepted E5/E6 observations per case, extracted
  exclusively from ``validation.status == "verified"`` probes' artifacts
* ``data/advisory_ranges.json``   (M3) normalised ``(op, version)`` advisory ranges
  parsed from the frozen ``advisory.*`` files (``null`` where the advisory has no
  machine-readable range)

Nothing under ``notes/``, ``data/public-snapshot/``, ``data/public-snapshot-2026-10-17/``,
``experiments/26cve/`` or the pilot/top-up directories is modified.  Every advisory
quote below is **verified verbatim** against the frozen advisory artifact at build time;
a missing quote aborts the build.

Usage:  python3 build_inputs.py            # write the three JSON inputs + build report
        python3 build_inputs.py --check     # verify quotes/counts only, write nothing
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))

import versioncmp  # noqa: E402

DATA_DIR = HERE / "data"
MAPPING_PATH = REPO / "notes" / "collector-mapping-30cve.md"
#: Public-data snapshot cohorts.  The 2026-10-11 cohort (D-026) holds the 30 original
#: CVE IDs; the 2026-10-17 cohort (D-035) holds the 2 top-up IDs and is **separate and
#: untouched** (its own manifest).  Nothing in this script writes to either root.
SNAPSHOT_DIR = REPO / "data" / "public-snapshot"
SNAPSHOT_COHORT_2026_10_17 = REPO / "data" / "public-snapshot-2026-10-17"
SNAPSHOT_DIRS = (SNAPSHOT_DIR, SNAPSHOT_COHORT_2026_10_17)
#: Mapping hash: D-030 as amended by D-032/D-033/D-034 and the 2026-10-17 top-up
#: (D-035/D-036 + `reviews/Review_mapping_topup_phanquyet_2026-10-17.md`) => 32 blocks.
#: Freeze of this 32-CVE version = D-037 (pending).
MAPPING_SHA256 = "c186250ea27797c7203161aa113e6484cbab3bd877cdfe979ba0174d2500e42c"

#: sha256 of the derived inputs **before** this build. Recorded so the changes of
#: this build are traceable. Directly preceding build = the V2 (D-033/D-034) build
#: that produced the V2 benchmark in `experiments/methods/output/benchmark-v2/`
#: (`experiments/methods/NOTE-v2-captures-benchmark-2026-10-16.md`); the content of
#: cases.json / advisory_ranges.json was proven unchanged vs the V1 build there.
#: The earlier 2026-10-15 fix-round / 2026-10-14 step-3 delivery hashes are kept in
#: `experiments/methods/NOTE-fix-round-2026-10-15.md` §2.
PREVIOUS_BUILD_SHA256 = {
    "experiments/methods/data/cases.json": "98dd5f6a1aa0709c952cf298a10c574da5eada7452dac01d4f33ca1e64829c1f",
    "experiments/methods/data/observations.json": "ba72d8071ddaa4a1fe990647793295f328e8de541bd66907108d65d9cad1a0a8",
    "experiments/methods/data/advisory_ranges.json": "32a51c8a8e4a2f0f22b6351f62f3554650a871e238c151de1464bbf3904c9f22",
}

REG = "experiments/26cve/registry.md"
PILOT = "experiments/pilot-3cve/README.md"
REPRO41773 = "experiments/reproduce-cve-2021-41773/README.md"
LINH = "review_pending"  # see notes: mapping review doc short name, expanded below
MAPPING_REVIEW = "reviews/Review_buoc2_mapping_phanquyet_2026-10-14.md"
DEC_FREEZE = "reviews/Xac_nhan_ban_khoa_mapping_D030_2026-10-14.md"

ARTIFACTS = {
    "batch0": "experiments/26cve/_batch0-stack/artifacts/http-observations.txt",
    "batch1": "experiments/26cve/_batch1-stack/artifacts/http-observations.txt",
    "batch3": "experiments/26cve/_batch3-stack/artifacts/http-observations.txt",
    "pilot": "experiments/pilot-3cve/artifacts/http-verification.txt",
    "41773_03": "experiments/reproduce-cve-2021-41773/03-lab-traversal.txt",
    "41773_04": "experiments/reproduce-cve-2021-41773/04-fixed-251-traversal.txt",
    "41773_05": "experiments/reproduce-cve-2021-41773/05-default-249-traversal.txt",
    "42013": "experiments/26cve/CVE-2021-42013/artifacts/42013-repro.txt",
    "5798": "experiments/26cve/CVE-2023-5798/artifacts/5798-http-observations.txt",
    # ---- V2 (2026-10-15/16) captures — `experiments/methods/captures-v2/` (D-033/D-034)
    "v2_1001000_rest_vuln": "experiments/methods/captures-v2/CVE-2017-1001000/8711-wp471-GET-rest-route-index-SUPPLEMENTARY.txt",
    "v2_1001000_rest_fixed": "experiments/methods/captures-v2/CVE-2017-1001000/8712-wp472-GET-rest-route-index-SUPPLEMENTARY.txt",
    "v2_10924_route_2fa_on": "experiments/methods/captures-v2/CVE-2024-10924/8081-2fa-on-POST-skip_onboarding.txt",
    "v2_10924_route_2fa_off": "experiments/methods/captures-v2/CVE-2024-10924/8081-2fa-off-POST-skip_onboarding.txt",
    "v2_10924_route_fixed": "experiments/methods/captures-v2/CVE-2024-10924/8082-fixed-9.1.2-2fa-on-POST-skip_onboarding.txt",
    "v2_3460_readme_vuln": "experiments/methods/captures-v2/CVE-2023-3460/8830-um266-GET-readme.txt",
    "v2_3460_readme_fixed": "experiments/methods/captures-v2/CVE-2023-3460/8831-um267-GET-readme.txt",
    "v2_3460_reg_vuln": "experiments/methods/captures-v2/CVE-2023-3460/8830-um266-GET-register-page.txt",
    "v2_3460_reg_fixed": "experiments/methods/captures-v2/CVE-2023-3460/8831-um267-GET-page_id6-AS-SPECIFIED.txt",
    # ---- top-up 2026-10-17 captures (`experiments/topup-2026-10-17/cases/`) ----
    "topup_23752_joomla_xml_427": "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-joomla.xml.raw.txt",
    "topup_23752_joomla_xml_428": "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-joomla.xml.raw.txt",
    "topup_23752_config_427": "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/427/GET-api-config-application_public-true.raw.txt",
    "topup_23752_config_428": "experiments/topup-2026-10-17/cases/CVE-2023-23752/artifacts/428/GET-api-config-application_public-true.raw.txt",
    "topup_6553_readme_137": "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/plugin-readme-137.raw.txt",
    "topup_6553_version_138": "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/version-observability-138.raw.txt",
    "topup_6553_benign_137_active": "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/d-137-active-benign-include.raw.txt",
    "topup_6553_benign_137_inactive": "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/d-137-inactive-benign-include.raw.txt",
    "topup_6553_benign_138_control": "experiments/topup-2026-10-17/cases/CVE-2023-6553/artifacts/c-138-active-benign-include-control.raw.txt",
}

HIDDEN_VERSION = "ẩn-version"
CONFIG_OFF = "config-tắt"
BACKPORT = "backport"
CPE_WRONG = "CPE-sai"


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cohort_dir(cve: str) -> Path:
    """Return the snapshot cohort directory that holds ``cve`` (2026-10-11 first).

    The two cohorts are separate frozen artifacts with their own manifests; a CVE
    lives in exactly one of them.  Resolution is by presence on disk, never by
    guessing, and a CVE present in neither aborts the build.
    """
    for d in SNAPSHOT_DIRS:
        if (d / cve).is_dir():
            return d
    raise SystemExit(f"no snapshot cohort holds {cve} (looked in {[str(d) for d in SNAPSHOT_DIRS]})")


def rel_repo(path: Path) -> str:
    p = Path(path).resolve()
    return str(p.relative_to(REPO)) if REPO in p.parents else str(path)


def norm_text(text: str) -> str:
    s = re.sub(r"<script.*?</script>", " ", text, flags=re.S | re.I)
    s = re.sub(r"<style.*?</style>", " ", s, flags=re.S | re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"[\u00a0\u2009\u202f]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def quote_pattern(quote: str) -> re.Pattern:
    return re.compile(r"\s+".join(re.escape(tok) for tok in quote.split()))


def require_quote(text: str, quote: str, where: str) -> None:
    if not quote_pattern(quote).search(text):
        raise SystemExit(f"QUOTE NOT FOUND in {where}: {quote!r}")


def load_mapping() -> dict:
    import yaml

    actual = sha256_file(MAPPING_PATH)
    if actual != MAPPING_SHA256:
        raise SystemExit(f"mapping sha256 mismatch: {actual} != {MAPPING_SHA256}")
    blocks = re.findall(r"```yaml\n(.*?)```", MAPPING_PATH.read_text(encoding="utf-8"), re.S)
    mapping: dict = {}
    for block in blocks:
        mapping.update(yaml.safe_load(block))
    assert len(mapping) == 32, len(mapping)
    return mapping


# --------------------------------------------------------------------------- #
# 1. CASES — transcribed from registry Appendix E (final) + pilot READMEs + D-020…D-024
# --------------------------------------------------------------------------- #
CVE_SPECS = [
    # ---------------- pilot cases (registry: pilot 4 CVEs) ----------------- #
    dict(cve="CVE-2021-41773", product="Apache HTTP Server 2.4.x", keys=["apache:http_server"],
         vuln_build="2.4.49", fixed_build="2.4.51", access="unauth",
         label_source=f"{REPRO41773} §Results (marker read 200 on the weakened build; 403 default; 404/400 fixed)",
         identity_tokens=["apache"], identity_family=None, tags=[],
         cases=[
             dict(id="weakened_249", build="2.4.49 (weakened <Directory /> 'Require all granted')",
                  config="misconfig_require_all_granted", label="Applicable", branch="", state_key="httpd2449_weakened_8083",
                  note="marker read out-of-docroot (200 + RQ-C1-LAB-MARKER) on 8083"),
             dict(id="default_249", build="2.4.49 (default <Directory /> 'Require all denied')",
                  config="default_require_all_denied", label="Not Applicable", branch="b", state_key="httpd2449_default_249_8081",
                  note="same affected image, default authorization: request traversed but denied (403) -> blocked path"),
             dict(id="fixed_251", build="2.4.51", config="default", label="Not Applicable", branch="a", state_key="httpd2451_8082",
                  note="fixed release rejects the encoded traversal (404 / 400)"),
         ]),
    dict(cve="CVE-2019-6340", product="Drupal core 8.6.x", keys=["drupal:drupal"],
         vuln_build="8.6.9", fixed_build="8.6.10",
         access="auth(content-creation; lab used HTTP basic auth admin per D-015)",
         label_source=f"{PILOT} §7 rows 4–7 (9 pilot states, 3 CVEs)",
         identity_tokens=["drupal"], identity_family="8", tags=[],
         cases=[
             dict(id="rest_on_869", build="8.6.9", config="rest_module_on", label="Applicable", branch="",
                  state_key="drupal869_rest_on", note="REST vector active; marker created"),
             dict(id="rest_off_jsonapi_on_869", build="8.6.9", config="rest_off_jsonapi_on", label="Applicable",
                  branch="", state_key="drupal869_jsonapi_on", note="alternative vector (contrib jsonapi 8.x-1.24) survives"),
             dict(id="both_off_869", build="8.6.9", config="both_off", label="Not Applicable", branch="b",
                  state_key="drupal869_both_off", note="REST 406 / JSON:API 404, no marker -> every path blocked"),
             dict(id="rest_on_8610_fixed", build="8.6.10", config="rest_module_on", label="Not Applicable", branch="a",
                  state_key="drupal8610_rest_on", note="fixed: allowed_classes=FALSE, no marker"),
         ]),
    dict(cve="CVE-2024-10924", product="Really Simple Security (WordPress plugin)",
         keys=["really-simple-plugins:really_simple_security"], vuln_build="9.1.1.1", fixed_build="9.1.2", access="unauth",
         label_source=f"{PILOT} §7 rows 1–3",
         identity_tokens=["really-simple"], identity_family=None, tags=[],
         cases=[
             dict(id="9_1_1_1_2fa_on", build="9.1.1.1", config="2fa_on", label="Applicable", branch="",
                  state_key="rss_9111_2fa_on", note="unauth skip_onboarding -> logged-in cookie"),
             dict(id="9_1_1_1_2fa_off", build="9.1.1.1", config="2fa_off", label="Not Applicable", branch="b",
                  state_key="rss_9111_2fa_off", note="2FA is the gate; route absent (404 rest_no_route)"),
             dict(id="9_1_2_2fa_on_fixed", build="9.1.2", config="2fa_on", label="Not Applicable", branch="a",
                  state_key="rss_912_2fa_on", note="patched build wp_die()s (HTTP 500, no cookie)"),
         ]),
    dict(cve="CVE-2020-12625", product="Roundcube Webmail 1.4.x", keys=["roundcube:webmail"],
         vuln_build="1.4.3", fixed_build="1.4.4", access="auth(victim reads HTML mail)",
         label_source=f"{PILOT} §7 rows 8–9",
         identity_tokens=["roundcube"], identity_family=None, tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: f"{PILOT} §4.4 + mapping decision_inputs E5→Unknown"},
         cases=[
             dict(id="1_4_3", build="1.4.3", config="default", label="Applicable", branch="", state_key="rc143",
                  note="CDATA emitted unescaped; script executed in the browser"),
             dict(id="1_4_4_fixed", build="1.4.4", config="default", label="Not Applicable", branch="a",
                  state_key="rc144", note="CDATA escaped; no execution"),
         ]),
    # ---------------- 26-CVE lab batch ------------------------------------- #
    dict(cve="CVE-2014-3704", product="Drupal core 7.x", keys=["drupal:drupal"], vuln_build="7.31", fixed_build="7.32",
         access="unauth", label_source="experiments/26cve/CVE-2014-3704/README.md §Ground-truth label",
         identity_tokens=["drupal"], identity_family="7", tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: "mapping p_core_version_lt_732 observable=false (family-only fingerprint)"},
         cases=[
             dict(id="vuln", build="7.31", config="default", label="Applicable", branch="", state_key="drupal7_731",
                  note="SQL error leaked the DB version"),
             dict(id="fixed", build="7.32", config="default", label="Not Applicable", branch="a", state_key="drupal7_732",
                  note="generic 1064 syntax error"),
         ]),
    dict(cve="CVE-2015-3440", product="WordPress core", keys=["wordpress:wordpress"], vuln_build="4.2-src",
         fixed_build="4.2.1", access="unauth",
         label_source="experiments/26cve/CVE-2015-3440/README.md §Ground-truth label",
         identity_tokens=["wordpress"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="4.2-src (deployment labelled WP 4.2.0)", config="default", label="Applicable",
                  branch="", state_key="wp420_src", note="generator token '4.2-src' (not a clean release)"),
             dict(id="fixed", build="4.2.1", config="default", label="Not Applicable", branch="a", state_key="wp421",
                  note="long comment not stored; no execution"),
         ]),
    dict(cve="CVE-2017-1001000", product="WordPress core", keys=["wordpress:wordpress"], vuln_build="4.7.1",
         fixed_build="4.7.2", access="unauth",
         label_source="experiments/26cve/CVE-2017-1001000/README.md §Ground-truth label",
         identity_tokens=["wordpress"], identity_family=None, tags=[CPE_WRONG],
         tags_provenance={CPE_WRONG: f"{MAPPING_REVIEW} B10 (CPE lists 4.7.2 as vulnerable; advisory states 4.7/4.7.1)"},
         cases=[
             dict(id="vuln", build="4.7.1", config="default", label="Applicable", branch="", state_key="wp471",
                  note="unauth REST edit; post content became the marker"),
             dict(id="fixed", build="4.7.2", config="default", label="Not Applicable", branch="a", state_key="wp472",
                  note="400 rest_invalid_param; post unchanged"),
         ]),
    dict(cve="CVE-2018-7600", product="Drupal core 8.x", keys=["drupal:drupal"], vuln_build="8.5.0",
         fixed_build="8.5.1", access="unauth",
         label_source="experiments/26cve/CVE-2018-7600/README.md §Ground-truth label",
         identity_tokens=["drupal"], identity_family="8", tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: "mapping p_core_version_in_affected_86 observable=false (family-only fingerprint)"},
         cases=[
             dict(id="vuln", build="8.5.0", config="default", label="Applicable", branch="", state_key="drupal8_850",
                  note="AJAX response carried the command output"),
             dict(id="fixed", build="8.5.1", config="default", label="Not Applicable", branch="a", state_key="drupal8_851",
                  note="no marker output"),
         ]),
    dict(cve="CVE-2018-7602", product="Drupal core 7.x", keys=["drupal:drupal"], vuln_build="7.58", fixed_build="7.59",
         access="auth(any authenticated user opening its own cancel confirm form; lab used uid 1)",
         label_source="experiments/26cve/CVE-2018-7602/README.md §Ground-truth label (D-023: accepted on the D7 pair)",
         identity_tokens=["drupal"], identity_family="7", tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: "mapping p_core_version_lt_759 observable=false (family-only fingerprint)"},
         cases=[
             dict(id="vuln", build="7.58", config="default", label="Applicable", branch="", state_key="drupal7_758",
                  note="marker created through the confirm-form chain"),
             dict(id="fixed", build="7.59", config="default", label="Not Applicable", branch="a", state_key="drupal7_759",
                  note="marker absent"),
         ]),
    dict(cve="CVE-2019-10692", product="WP plugin WP Google Maps (codecabin)", keys=["codecabin:wp_go_maps"],
         vuln_build="7.11.17", fixed_build="7.11.18", access="unauth",
         label_source="experiments/26cve/CVE-2019-10692/README.md §Ground-truth label",
         identity_tokens=["wp-google-maps"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="7.11.17", config="default", label="Applicable", branch="", state_key="wgm_71117",
                  note="injected fields returned the marker / user hashes"),
             dict(id="fixed", build="7.11.18", config="default", label="Not Applicable", branch="a", state_key="wgm_71118",
                  note="injected fields ignored"),
         ]),
    dict(cve="CVE-2019-6341", product="Drupal core 8.6.x", keys=["drupal:drupal"], vuln_build="8.6.12",
         fixed_build="8.6.13", access="unauth",
         label_source="experiments/26cve/CVE-2019-6341/README.md §Ground-truth label + D-024",
         identity_tokens=["drupal"], identity_family="8", tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: "mapping p_core_version_lt_8613 observable=false (family-only fingerprint)"},
         cases=[
             dict(id="unresolved", build="8.6.12", config="registration_open_user_picture", label="Unresolved", branch="",
                  state_key="drupal8_8612",
                  note="stored-file primitive reproduced (8.6.12 stores the extension-less _0 file, 8.6.13 rejects) but "
                       "in-browser JS execution was not obtained -> no label (D-024, manual reproduction pending)"),
         ]),
    dict(cve="CVE-2019-8942", product="WordPress core", keys=["wordpress:wordpress"], vuln_build="5.0.0",
         fixed_build="5.0.1", access="auth(author)", label_source="experiments/26cve/CVE-2019-8942/README.md §Ground-truth label",
         identity_tokens=["wordpress"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="5.0.0", config="author_account_default_theme", label="Applicable", branch="",
                  state_key="wp500", note="marker created + shell image planted in the theme dir"),
             dict(id="fixed", build="5.0.1", config="author_account_default_theme", label="Not Applicable", branch="a",
                  state_key="wp501", note="no marker, meta_input ignored"),
         ]),
    dict(cve="CVE-2020-12640", product="Roundcube Webmail 1.4.x", keys=["roundcube:webmail"], vuln_build="1.4.3",
         fixed_build="1.4.4", access="unauth (public installer needed to set the config option)",
         label_source="experiments/26cve/CVE-2020-12640/README.md §Ground-truth label (D-023: default NA-b + config-on rows)",
         identity_tokens=["roundcube"], identity_family=None, tags=[CONFIG_OFF, HIDDEN_VERSION],
         tags_provenance={CONFIG_OFF: f"{REG} Appendix E scenario_tags", HIDDEN_VERSION: "mapping decision_inputs E5→Unknown"},
         cases=[
             dict(id="config_off", build="1.4.3", config="default_no_installer", label="Not Applicable", branch="b",
                  state_key="rc143_default_config_off", note="official image has no /installer/ -> config option cannot be set"),
             dict(id="config_on_vuln", build="1.4.3", config="config_on_installer_simulated", label="Applicable", branch="",
                  state_key="rc143_config_on", note="simulated installer-set 'plugins' traversal -> marker (fixture: planted /tmp/rqp)"),
             dict(id="config_on_fixed", build="1.4.4", config="config_on_installer_simulated", label="Not Applicable",
                  branch="a", state_key="rc144_config_on", note="plugin name validated; no include"),
         ]),
    dict(cve="CVE-2020-12641", product="Roundcube Webmail 1.4.x", keys=["roundcube:webmail"], vuln_build="1.4.3",
         fixed_build="1.4.4", access="unauth (public installer needed; trigger needs a mail session in the lab)",
         label_source="experiments/26cve/CVE-2020-12641/README.md §Ground-truth label (D-023)",
         identity_tokens=["roundcube"], identity_family=None, tags=[CONFIG_OFF, HIDDEN_VERSION],
         tags_provenance={CONFIG_OFF: f"{REG} Appendix E scenario_tags", HIDDEN_VERSION: "mapping decision_inputs E5→Unknown"},
         cases=[
             dict(id="config_off", build="1.4.3", config="default_no_installer_no_convert", label="Not Applicable", branch="b",
                  state_key="rc143_default_config_off", note="no installer and no convert path -> config option cannot be set"),
             dict(id="config_on_vuln", build="1.4.3", config="config_on_installer_simulated", label="Applicable", branch="",
                  state_key="rc143_config_on", note="im_convert_path metacharacters -> marker (fixture: >240px image thumbnail)"),
             dict(id="config_on_fixed", build="1.4.4", config="config_on_installer_simulated", label="Not Applicable",
                  branch="a", state_key="rc144_config_on", note="escapeshellcmd neutralises the metacharacters"),
         ]),
    dict(cve="CVE-2020-13671", product="Drupal core 8.9.x", keys=["drupal:drupal"], vuln_build="8.9.8",
         fixed_build="8.9.9", access="auth(upload/content-creation; fixture field)",
         label_source="experiments/26cve/CVE-2020-13671/README.md §Ground-truth label (D-023)",
         identity_tokens=["drupal"], identity_family="8", tags=[CONFIG_OFF, HIDDEN_VERSION],
         tags_provenance={CONFIG_OFF: f"{REG} Appendix E scenario_tags",
                          HIDDEN_VERSION: "mapping p_core_version_lt_899 observable=false (family-only fingerprint)"},
         cases=[
             dict(id="config_off", build="8.9.8", config="default_article_image_field_only", label="Not Applicable",
                  branch="b", state_key="drupal8_898", note="no file field with an unsafe extension -> no reachable path"),
             dict(id="config_on_vuln", build="8.9.8", config="file_field_allows_png_php", label="Applicable", branch="",
                  state_key="drupal8_898", note="file_munge_filename kept poc.php.png (unsafe internal extension)"),
             dict(id="config_on_fixed", build="8.9.9", config="file_field_allows_png_php", label="Not Applicable",
                  branch="a", state_key="drupal8_899", note="munged to poc.php_.png; file_validate rejects"),
         ]),
    dict(cve="CVE-2020-25213", product="WP plugin File Manager (wp-file-manager)", keys=["filemanagerpro:file_manager"],
         vuln_build="6.0", fixed_build="8.0.6 (advisory fix 6.9; 6.9 zip unavailable, D-021)",
         access="unauth", label_source="experiments/26cve/CVE-2020-25213/README.md §Ground-truth label",
         identity_tokens=["wp-file-manager", "file manager"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="6.0", config="default", label="Applicable", branch="", state_key="wfm_60",
                  note="unauth connector upload -> GET executes -> marker"),
             dict(id="fixed", build="8.0.6", config="default", label="Not Applicable", branch="a", state_key="wfm_806",
                  note="connector removed (301); no marker"),
         ]),
    dict(cve="CVE-2021-23017", product="nginx (Ubuntu jammy package)", keys=["f5:nginx"],
         vuln_build=None, fixed_build="1.20.1 upstream / 1.18.0-6ubuntu9 jammy backport",
         access="unauth", label_source="experiments/26cve/CVE-2021-23017/README.md §Ground-truth label (D-020.2)",
         identity_tokens=["nginx"], identity_family=None, tags=[BACKPORT, HIDDEN_VERSION],
         tags_provenance={BACKPORT: f"{REG} table row + scenario_tags",
                          HIDDEN_VERSION: f"{REG} table row ('ẩn-version/build-identity limitation')"},
         cases=[
             dict(id="backport_na_a", build="1.18.0-6ubuntu14.21 (jammy backport, already patched)",
                  config="default", label="Not Applicable", branch="a", state_key="nginx_jammy_backport",
                  note="build identity + patch reference establish branch (a); no exploitation attempted"),
         ]),
    dict(cve="CVE-2021-24917", product="WP plugin WPS Hide Login", keys=["wpserveur:wps_hide_login"],
         vuln_build="1.9", fixed_build="1.9.1", access="unauth",
         label_source="experiments/26cve/CVE-2021-24917/README.md §Ground-truth label",
         identity_tokens=["wps-hide-login"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="1.9", config="secret_login_configured", label="Applicable", branch="",
                  state_key="whl_19", note="referer bypass disclosed the secret login slug"),
             dict(id="fixed", build="1.9.1", config="secret_login_configured", label="Not Applicable", branch="a",
                  state_key="whl_191", note="redirects to /?404; secret not revealed"),
         ]),
    dict(cve="CVE-2021-29447", product="WordPress core (PHP 8)", keys=["wordpress:wordpress"], vuln_build="5.7.0",
         fixed_build="5.7.1", access="auth(author; upload_files)",
         label_source="experiments/26cve/CVE-2021-29447/README.md §Ground-truth label",
         identity_tokens=["wordpress"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="5.7.0 (PHP 8.0.3)", config="php8_author_upload", label="Applicable", branch="",
                  state_key="wp570_php803", note="DTD fetched, marker exfiltrated out-of-band"),
             dict(id="fixed", build="5.7.1 (PHP 8.0.6)", config="php8_author_upload", label="Not Applicable", branch="a",
                  state_key="wp571_php806", note="upload accepted, no DTD fetch"),
         ]),
    dict(cve="CVE-2021-42013", product="Apache HTTP Server 2.4.x", keys=["apache:http_server"], vuln_build="2.4.50",
         fixed_build="2.4.51", access="unauth",
         label_source="experiments/26cve/CVE-2021-42013/README.md §Ground-truth label",
         identity_tokens=["apache"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="2.4.50 (weakened <Directory /> 'Require all granted')",
                  config="misconfig_require_all_granted", label="Applicable", branch="", state_key="httpd2450_8860",
                  note="double-encoded traversal -> 200 + marker"),
             dict(id="fixed", build="2.4.51", config="default", label="Not Applicable", branch="a", state_key="httpd2451_8861",
                  note="same request -> 400"),
         ]),
    dict(cve="CVE-2021-44026", product="Roundcube Webmail 1.4.x", keys=["roundcube:webmail"], vuln_build="1.4.11",
         fixed_build="1.4.12", access="auth(test/test; mail session needed for the chain)",
         label_source="experiments/26cve/CVE-2021-44026/README.md §Ground-truth label",
         identity_tokens=["roundcube"], identity_family=None, tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: "mapping decision_inputs E5→Unknown"},
         cases=[
             dict(id="vuln", build="1.4.11", config="default_auth_session", label="Applicable", branch="",
                  state_key="rc1411", note="injected SLEEP(6) executed (6.07 s vs 0.05 s)"),
             dict(id="fixed", build="1.4.12", config="default_auth_session", label="Not Applicable", branch="a",
                  state_key="rc1412", note="_sort filtered; export 0.05 s"),
         ]),
    dict(cve="CVE-2022-21661", product="WordPress core (+ fixture plugin)", keys=["wordpress:wordpress"], vuln_build="5.8.2",
         fixed_build="5.8.3", access="unauth",
         label_source="experiments/26cve/CVE-2022-21661/README.md §Ground-truth label",
         identity_tokens=["wordpress"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="5.8.2", config="fixture_ele_custom_skin_3_1_3", label="Applicable", branch="",
                  state_key="wp582", note="time-based signal 5.03 s + MariaDB log"),
             dict(id="fixed", build="5.8.3", config="fixture_ele_custom_skin_3_1_3", label="Not Applicable", branch="a",
                  state_key="wp583", note="0.018 s, no injected SQL"),
         ]),
    dict(cve="CVE-2023-2745", product="WordPress core", keys=["wordpress:wordpress"], vuln_build="6.2.0",
         fixed_build="6.2.1", access="unauth",
         label_source="experiments/26cve/CVE-2023-2745/README.md §Ground-truth label",
         identity_tokens=["wordpress"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="6.2.0", config="default_planted_mo", label="Applicable", branch="", state_key="wp620",
                  note="traversal loaded the planted .mo; translated marker shown"),
             dict(id="fixed", build="6.2.1", config="default_planted_mo", label="Not Applicable", branch="a", state_key="wp621",
                  note="sanitize_locale_name strips './'; marker absent"),
         ]),
    dict(cve="CVE-2023-28121", product="WooCommerce Payments (WooPayments)", keys=["automattic:woocommerce_payments", "automattic:woopayments"],
         vuln_build="5.6.1 (+ WooCommerce 7.5.1)", fixed_build="5.6.2", access="unauth",
         label_source="experiments/26cve/CVE-2023-28121/README.md §Ground-truth label",
         identity_tokens=["woocommerce-payments", "woopayments"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="5.6.1", config="default", label="Applicable", branch="", state_key="wcpay_561",
                  note="forged platform-checkout header created an administrator (201)"),
             dict(id="fixed", build="5.6.2", config="default", label="Not Applicable", branch="a", state_key="wcpay_562",
                  note="401; no user created"),
         ]),
    dict(cve="CVE-2023-32243", product="WP plugin Essential Addons for Elementor", keys=["wpdeveloper:essential_addons_for_elementor"],
         vuln_build="5.7.1 (+ Elementor 3.5.6)", fixed_build="5.7.2", access="unauth",
         label_source="experiments/26cve/CVE-2023-32243/README.md §Ground-truth label",
         identity_tokens=["essential-addons"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="5.7.1", config="default_elementor_active", label="Applicable", branch="",
                  state_key="ea_571", note="password reset for admin via unauth nonce"),
             dict(id="fixed", build="5.7.2", config="default_elementor_active", label="Not Applicable", branch="a",
                  state_key="ea_572", note="reset key validated; password unchanged"),
         ]),
    dict(cve="CVE-2023-3460", product="WP plugin Ultimate Member", keys=["ultimatemember:ultimate_member"],
         vuln_build="2.6.6", fixed_build="2.6.7", access="unauth",
         label_source="experiments/26cve/CVE-2023-3460/README.md §Ground-truth label",
         identity_tokens=["ultimate-member"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="2.6.6", config="open_registration_form", label="Applicable", branch="",
                  state_key="um_266", note="accented metakey bypass created an administrator"),
             dict(id="fixed", build="2.6.7", config="open_registration_form", label="Not Applicable", branch="a",
                  state_key="um_267", note="no admin-capable user created"),
         ]),
    dict(cve="CVE-2023-5631", product="Roundcube Webmail 1.4.x", keys=["roundcube:webmail"], vuln_build="1.4.11",
         fixed_build="1.5.5 (same commit as 1.4.15)", access="auth(victim reads message; attacker delivers mail via SMTP)",
         label_source="experiments/26cve/CVE-2023-5631/README.md §Ground-truth label + D-024",
         identity_tokens=["roundcube"], identity_family=None, tags=[HIDDEN_VERSION, CPE_WRONG],
         tags_provenance={HIDDEN_VERSION: "mapping decision_inputs E5→Unknown",
                          CPE_WRONG: f"{MAPPING_REVIEW} B6 (NVD 1.6.3 vs CPE 1.6.4 range statements differ)"},
         cases=[
             dict(id="unresolved", build="1.4.11", config="default_auth_mail", label="Unresolved", branch="",
                  state_key="rc1411",
                  note="server-side injection difference confirmed (affected keeps the unsanitised SVG data-URI, fixed washes it) "
                       "but chromium-1208 blocks <use href=\"data:\"> -> no execution -> no label (D-024)"),
         ]),
    dict(cve="CVE-2023-5798", product="WP plugin Assistant", keys=["fastlinemedia:assistant"], vuln_build="1.4.3",
         fixed_build="1.4.4", access="auth(Editor+)",
         label_source="experiments/26cve/CVE-2023-5798/README.md §Ground-truth label",
         identity_tokens=["assistant"], identity_family=None, tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: f"{REG} Appendix A scenario_tags ('plugin ver not unauth-observable')"},
         cases=[
             dict(id="vuln", build="1.4.3", config="editor_account_default", label="Applicable", branch="",
                  state_key="asst_143", note="attacker listener received GET /rq-c1-ssrf"),
             dict(id="fixed", build="1.4.4", config="editor_account_default", label="Not Applicable", branch="a",
                  state_key="asst_144", note="wp_safe_remote_get blocked the private host"),
         ]),
    dict(cve="CVE-2024-28000", product="WP plugin LiteSpeed Cache", keys=["litespeedtech:litespeed_cache"],
         vuln_build="6.3.0.1", fixed_build="6.4", access="unauth",
         label_source="experiments/26cve/CVE-2024-28000/README.md §Ground-truth label (D-021.2 hash deviation)",
         identity_tokens=["litespeed-cache"], identity_family=None, tags=[],
         cases=[
             dict(id="vuln", build="6.3.0.1", config="crawler_on", label="Applicable", branch="", state_key="lsc_6301",
                  note="forged cookies operated as user 1 (201)"),
             dict(id="fixed", build="6.4", config="crawler_on", label="Not Applicable", branch="a", state_key="lsc_64",
                  note="no hash stored; 401"),
         ]),
    dict(cve="CVE-2024-37383", product="Roundcube Webmail 1.5.x", keys=["roundcube:webmail"], vuln_build="1.5.6",
         fixed_build="1.5.7", access="auth(victim reads message; attacker delivers mail via SMTP)",
         label_source="experiments/26cve/CVE-2024-37383/README.md §Ground-truth label",
         identity_tokens=["roundcube"], identity_family=None, tags=[HIDDEN_VERSION],
         tags_provenance={HIDDEN_VERSION: "mapping decision_inputs E5→Unknown"},
         cases=[
             dict(id="vuln", build="1.5.6", config="default_auth_mail", label="Applicable", branch="", state_key="rc156",
                  note="click on the animated link executed JS (window.__rq=1)"),
             dict(id="fixed", build="1.5.7", config="default_auth_mail", label="Not Applicable", branch="a", state_key="rc157",
                  note="<animate> blocked; no execution"),
         ]),
    # ---------------- top-up 2 CVE (D-035 list / D-036 labels, 2026-10-17) -- #
    dict(cve="CVE-2023-23752", product="Joomla! CMS (core)", keys=["joomla:joomla\\!"],
         vuln_build="4.2.7", fixed_build="4.2.8", access="unauth",
         label_source=f"{REG} Appendix F (D-035/D-036 accepted 2026-10-17)",
         identity_tokens=["joomla"], identity_family=None, tags=[],
         cases=[
             dict(id="4_2_7_default", build="4.2.7", config="default_webservices_enabled", label="Applicable",
                  branch="", state_key="jl427_default",
                  note="unauth ?public=true -> 200 JSON:API + JConfig object incl. the planted canary password/secret"),
             dict(id="4_2_8_default_fixed", build="4.2.8", config="default_webservices_enabled", label="Not Applicable",
                  branch="a", state_key="jl428_default",
                  note="401 {\"errors\":[{\"title\":\"Forbidden\"}]}; canary absent (patched build)"),
         ]),
    dict(cve="CVE-2023-6553", product="WP plugin Backup Migration (backup-backup)",
         keys=["backupbliss:backup_migration"], vuln_build="1.3.7", fixed_build="1.3.8", access="unauth",
         label_source=f"{REG} Appendix F (D-035/D-036 accepted 2026-10-17)",
         identity_tokens=["backup-backup"], identity_family=None, tags=[],
         cases=[
             dict(id="1_3_7_active", build="1.3.7", config="plugin_active", label="Applicable", branch="",
                  state_key="bb137_active", note="filter-chain POST -> marker written out-of-band (D-015)"),
             dict(id="1_3_7_inactive", build="1.3.7", config="plugin_inactive_files_present", label="Applicable",
                  branch="", state_key="bb137_inactive",
                  note="deactivated, files present -> marker written (installed is enough, D-036)"),
             dict(id="1_3_8_active_fixed", build="1.3.8", config="plugin_active", label="Not Applicable", branch="a",
                  state_key="bb138_active", note="filterChainFix() rejects the value; no marker (patched build)"),
         ]),
]


def build_cases(mapping: dict) -> dict:
    cases = []
    for spec in CVE_SPECS:
        cve = spec["cve"]
        if cve not in mapping:
            raise SystemExit(f"case spec for {cve} has no mapping block")
        for cs in spec["cases"]:
            tags = list(spec.get("tags") or []) + list(cs.get("tags") or [])
            prov = dict(spec.get("tags_provenance") or {})
            for t in cs.get("tags") or []:
                prov.setdefault(t, "derived: config-blocked state (branch b) per registry/README")
            cases.append({
                "case_id": f"{cve}__{cs['id']}",
                "cve_id": cve,
                "product": spec["product"],
                "product_key": spec["product"],
                "cpe_vendor_product": spec["keys"],
                "vuln_build": spec["vuln_build"],
                "fixed_build": spec["fixed_build"],
                "build": cs["build"],
                "config_state": cs["config"],
                "access_model": spec["access"],
                "ground_truth_label": cs["label"],
                "label_branch": cs["branch"],
                "scenario_tags": sorted({*tags}),
                "scenario_tags_provenance": {t: prov.get(t, "registry/README (transcribed)") for t in sorted({*tags})},
                "identity_tokens": spec["identity_tokens"],
                "identity_family": spec["identity_family"],
                "artifact_state_key": cs.get("state_key"),
                "label_source": spec["label_source"],
                "config_gated": bool(spec.get("config_gated")),
                "notes": cs.get("note", ""),
            })
    ids = [c["case_id"] for c in cases]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate case ids")
    hist = {}
    for c in cases:
        hist[c["ground_truth_label"]] = hist.get(c["ground_truth_label"], 0) + 1
    unresolved = sorted({c["cve_id"] for c in cases if c["ground_truth_label"] == "Unresolved"})
    return {
        "generated_at_utc": now_utc(),
        "generated_by": "experiments/methods/build_inputs.py (engineer, step 3 phase A)",
        "sources": {
            "mapping": {"path": "notes/collector-mapping-30cve.md", "sha256": MAPPING_SHA256,
                        "decision": "D-030 (freeze); amended by D-032 "
                                    "(probe_rest_root verified -> pending), D-033 (two probe request paths corrected), "
                                    "D-034 (4 V2 captures -> probe_rest_root / probe_two_fa_route / "
                                    "observe_plugin_readme_version / probe_um_register_form verified) and the "
                                    "2026-10-17 top-up (D-035/D-036 + Review_mapping_topup_phanquyet_2026-10-17.md: "
                                    "2 CVE blocks merged, 4 probes verified) -> 32 blocks; freeze of the 32-CVE "
                                    "version = D-037 (pending)"},
            "snapshot": {"path": "data/public-snapshot", "decision": "D-026",
                         "cohorts": [{"path": "data/public-snapshot", "snapshot_date": "2026-10-11", "decision": "D-026"},
                                     {"path": "data/public-snapshot-2026-10-17", "snapshot_date": "2026-10-17",
                                      "decision": "D-035 (separate top-up cohort)"}]},
            "labels": [REG, PILOT, REPRO41773, "experiments/26cve/CVE-*/README.md",
                       "experiments/topup-2026-10-17/cases/*/README.md", "context/CURRENT_STATE.md §22–§53",
                       MAPPING_REVIEW, DEC_FREEZE],
            "decisions": ["D-014", "D-015", "D-020", "D-021", "D-022", "D-023", "D-024", "D-026", "D-030",
                          "D-032", "D-033", "D-034", "D-035", "D-036"],
        },
        "counting_rules": {
            "unit": "case = (product, build, config, CVE, access model)",
            "config_gated_cves": ["CVE-2020-13671", "CVE-2020-12640", "CVE-2020-12641"],
            "note": "config-gated CVEs carry 3 cases each (config-off NA-b, config-on vuln Applicable, config-on fixed NA-a); "
                    "CVE-2021-23017 is a single Not-Applicable(a) backport case; the 2 Unresolved CVEs carry 1 case each "
                    "(single registry row, label Unresolved, excluded from the metric denominator); the top-up adds "
                    "2 Joomla cases (4.2.7 / 4.2.8) and 3 Backup Migration cases (1.3.7 active / 1.3.7 inactive / 1.3.8) "
                    "per `experiments/26cve/registry.md` Appendix F (D-036).",
            "n_unique_cves_vs_cases": f"{len({c['cve_id'] for c in cases}) - len(unresolved)} resolved CVE IDs, "
                                      f"{len({c['cve_id'] for c in cases})} CVE IDs present, {len(cases)} cases",
        },
        "counts": {
            "n_unique_cves": len({c["cve_id"] for c in cases}),
            "n_cases": len(cases),
            "n_labels": hist,
            "n_unresolved_cves": len(unresolved),
            "unresolved_cves": unresolved,
            "n_cases_excluded_from_metrics": sum(1 for c in cases if c["ground_truth_label"] == "Unresolved"),
        },
        "cases": cases,
    }


# --------------------------------------------------------------------------- #
# 2. OBSERVATIONS — only from validation.status == "verified" probes
# --------------------------------------------------------------------------- #
# Extraction specs for the 18 verified probes (D-030).  Each spec: artifact file
# key, marker per artifact_state_key, regex, value kind, product label.
VERIFIED_EXTRACTORS = {
    ("CVE-2014-3704", "observe_xgenerator_drupal"): dict(
        file="batch1", markers={"drupal7_731": "## drupal 7.31 (8901)", "drupal7_732": "## drupal 7.32 (8902)"},
        regex=r"X-Generator:\s*(Drupal\s+\d+)", kind="family", product="Drupal"),
    ("CVE-2015-3440", "observe_wp_generator"): dict(
        file="batch3", markers={"wp420_src": "## 8731 (WP 4.2.0)", "wp421": "## 8732 (WP 4.2.1)"},
        regex=r'generator:\s*content="WordPress\s+([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2017-1001000", "observe_wp_generator"): dict(
        file="batch3", markers={"wp471": "## 8711 (WP 4.7.1)", "wp472": "## 8712 (WP 4.7.2)"},
        regex=r'generator:\s*content="WordPress\s+([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2017-1001000", "probe_rest_root"): dict(
        # D-033: request is `GET /?rest_route=/`; V2 capture (D-034) is the
        # plain-permalink REST index.  The 200-text/html `/wp-json/` files are the
        # status-only trap and are deliberately NOT used here.
        file=None, files={"wp471": "v2_1001000_rest_vuln", "wp472": "v2_1001000_rest_fixed"},
        markers={}, regex=r"HTTP/1\.[01]\s+(\d{3})", kind="rest_routes", product="WordPress"),
    ("CVE-2018-7600", "observe_xgenerator_drupal"): dict(
        file="batch1", markers={"drupal8_850": "## drupal 8.5.0 (8903)", "drupal8_851": "## drupal 8.5.1 (8904)"},
        regex=r"X-Generator:\s*(Drupal\s+\d+)", kind="family", product="Drupal"),
    ("CVE-2019-6341", "observe_xgenerator_drupal"): dict(
        file="batch1", markers={"drupal8_8612": "## drupal 8.6.12 (8909)", "drupal8_8613": "## drupal 8.6.13 (8910)"},
        regex=r"X-Generator:\s*(Drupal\s+\d+)", kind="family", product="Drupal"),
    ("CVE-2019-8942", "observe_wp_generator"): dict(
        file="batch0", markers={"wp500": "## CVE-2019-8942  WP 5.0.0 (vuln)", "wp501": "## CVE-2019-8942  WP 5.0.1 (fixed)"},
        regex=r'generator meta:\s*content="WordPress ([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2020-13671", "observe_xgenerator_drupal"): dict(
        file="batch1", markers={"drupal8_898": "## drupal 8.9.8 (8907)", "drupal8_899": "## drupal 8.9.9 (8908)"},
        regex=r"X-Generator:\s*(Drupal\s+\d+)", kind="family", product="Drupal"),
    ("CVE-2021-29447", "observe_wp_generator"): dict(
        file="batch0",
        markers={"wp570_php803": "## CVE-2021-29447 WP 5.7.0 (vuln)", "wp571_php806": "## CVE-2021-29447 WP 5.7.1 (fixed)"},
        regex=r'generator meta:\s*content="WordPress ([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2021-29447", "observe_php_version"): dict(
        file="batch0",
        markers={"wp570_php803": "## CVE-2021-29447 WP 5.7.0 (vuln)", "wp571_php806": "## CVE-2021-29447 WP 5.7.1 (fixed)"},
        regex=r"X-Powered-By: PHP/([0-9.]+)", kind="php8", product="PHP"),
    ("CVE-2021-41773", "observe_server_header"): dict(
        file=None,
        files={"httpd2449_weakened_8083": "41773_03", "httpd2449_default_249_8081": "41773_05", "httpd2451_8082": "41773_04"},
        markers={}, regex=r"Server:\s*(Apache/[0-9.]+)", kind="version", product="Apache"),
    ("CVE-2021-42013", "observe_server_header"): dict(
        file="42013", markers={"httpd2450_8860": "### CVE-2021-42013 vuln-2.4.50 (port 8860)",
                               "httpd2451_8861": "### CVE-2021-42013 fixed-2.4.51 (port 8861)"},
        regex=r"Server:\s*Server:\s*(Apache/[0-9.]+)", kind="version", product="Apache"),
    ("CVE-2022-21661", "observe_wp_generator"): dict(
        file="batch0", markers={"wp582": "## CVE-2022-21661 WP 5.8.2 (vuln)", "wp583": "## CVE-2022-21661 WP 5.8.3 (fixed)"},
        regex=r'generator meta:\s*content="WordPress ([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2022-21661", "observe_fixture_asset_version"): dict(
        file="batch0", markers={"wp582": "## CVE-2022-21661 WP 5.8.2 (vuln)", "wp583": "## CVE-2022-21661 WP 5.8.3 (fixed)"},
        regex=r"ECS fixture asset:\s*(.*)", kind="fixture_asset", product="ele-custom-skin"),
    ("CVE-2023-2745", "observe_wp_generator"): dict(
        file="batch3", markers={"wp620": "## 8721 (WP 6.2.0)", "wp621": "## 8722 (WP 6.2.1)"},
        regex=r'generator:\s*content="WordPress\s+([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2023-5798", "probe_home_no_assistant_version"): dict(
        file="5798", markers={"asst_143": "## http://127.0.0.1:8611 (assistant 1.4.3)",
                              "asst_144": "## http://127.0.0.1:8612 (assistant 1.4.4)"},
        regex=r"assistant asset:\s*(.*)", kind="negative_version", product="Assistant"),
    ("CVE-2024-10924", "observe_plugin_asset_version"): dict(
        file="pilot",
        markers={"rss_9111_2fa_on": "-- [wp-vuln-9.1.1.1] http://127.0.0.1:8081",
                 "rss_9111_2fa_off": "-- [wp-vuln-9.1.1.1] http://127.0.0.1:8081",
                 "rss_912_2fa_on": "-- [wp-fixed-9.1.2] http://127.0.0.1:8082"},
        regex=r"plugin asset ver\s*->\s*ver=([0-9.]+)", kind="version", product="really-simple-ssl"),
    ("CVE-2024-10924", "observe_wp_generator"): dict(
        file="pilot",
        markers={"rss_9111_2fa_on": "-- [wp-vuln-9.1.1.1] http://127.0.0.1:8081",
                 "rss_9111_2fa_off": "-- [wp-vuln-9.1.1.1] http://127.0.0.1:8081",
                 "rss_912_2fa_on": "-- [wp-fixed-9.1.2] http://127.0.0.1:8082"},
        regex=r'generator meta\s*->\s*content="WordPress ([^"]+)"', kind="version", product="WordPress"),
    ("CVE-2024-10924", "probe_two_fa_route"): dict(
        # D-033: request is `POST /?rest_route=/reallysimplessl/v1/two_fa/skip_onboarding`, body `{}`.
        # One response carries BOTH conditions (R4: 2 extractions = 1 request, D-034):
        #   400 rest_missing_callback_param -> p_2fa_enabled = True  AND p_skip_onboarding_route = True
        #   404 rest_no_route                -> p_2fa_enabled = False AND p_skip_onboarding_route = False
        file=None, files={"rss_9111_2fa_on": "v2_10924_route_2fa_on",
                          "rss_9111_2fa_off": "v2_10924_route_2fa_off",
                          "rss_912_2fa_on": "v2_10924_route_fixed"},
        markers={}, regex=r"HTTP/1\.[01]\s+(\d{3})", kind="rest_route_presence", product="really-simple-ssl",
        also_maps_to=["p_skip_onboarding_route"]),
    ("CVE-2023-3460", "observe_plugin_readme_version"): dict(
        # D-034: `Stable tag: 2.6.6` (8830) vs `Stable tag: 2.6.7` (8831).
        # `product` carries the plugin slug because E5 matches the case identity
        # token (CPE-style slug `ultimate-member`), not the display name.
        file=None, files={"um_266": "v2_3460_readme_vuln", "um_267": "v2_3460_readme_fixed"},
        markers={}, regex=r"Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", kind="version", product="ultimate-member"),
    ("CVE-2023-3460", "probe_um_register_form"): dict(
        # D-034: `GET /?page_id=6` -> 200 + `um-form` + `user_login-7` + `_wpnonce` on BOTH
        # states after the 2026-10-16 fixed-fixture alignment.  The fixed-state artifact is
        # `8831-um267-GET-page_id6-AS-SPECIFIED.txt` (the superseding re-capture): the
        # same-named `8831-um267-GET-register-page.txt` is the pre-fix `?page_id=12` capture
        # and is marked STALE by the lab (form id 6 -> `user_login-6`).
        file=None, files={"um_266": "v2_3460_reg_vuln", "um_267": "v2_3460_reg_fixed"},
        markers={}, regex=r"HTTP/1\.[01]\s+(\d{3})", kind="form_markers", product="ultimate-member"),
    # ---- top-up 2026-10-17 captures (mapping amendment; D-035/D-036) -------- #
    ("CVE-2023-23752", "observe_joomla_version"): dict(
        # `GET /administrator/manifests/files/joomla.xml` -> 200 application/xml,
        # `<version>4.2.7</version>` (427) vs `<version>4.2.8</version>` (428).
        # `<?xml version="1.0"` does not match the `<version>` element regex.
        file=None, files={"jl427_default": "topup_23752_joomla_xml_427",
                          "jl428_default": "topup_23752_joomla_xml_428"},
        markers={}, regex=r"<version>\s*([0-9][0-9A-Za-z.\-]*)\s*</version>", kind="version", product="Joomla"),
    ("CVE-2023-23752", "probe_config_application_public"): dict(
        # `GET /api/index.php/v1/config/application?public=true`:
        #   200 + JSON:API envelope + JConfig keys (incl. secret keys) -> True
        #   401 + {"errors":[{"title":"Forbidden"}]} (app-level, JoomlaAPI)  -> False
        file=None, files={"jl427_default": "topup_23752_config_427",
                          "jl428_default": "topup_23752_config_428"},
        markers={}, regex=r"HTTP/1\.[01]\s+(\d{3})", kind="config_disclosure", product="Joomla"),
    ("CVE-2023-6553", "observe_plugin_readme_version"): dict(
        # `readme.txt` -> `Stable tag: 1.3.7` / `Stable tag: 1.3.8`.  The 1.3.8 artifact is a
        # multi-request capture, so the readme response is sliced by its request marker; the
        # 1.3.7 capture is a single request whose `Stable tag` sits in the head (the file is
        # truncated at 32 KB by the lab, well after the line).
        file=None, files={"bb137_active": "topup_6553_readme_137",
                          "bb137_inactive": "topup_6553_readme_137",
                          "bb138_active": "topup_6553_version_138"},
        sections={"bb137_active": "### GET /wp-content/plugins/backup-backup/readme.txt (plugin 1.3.7 active)",
                  "bb137_inactive": "### GET /wp-content/plugins/backup-backup/readme.txt (plugin 1.3.7 active)",
                  "bb138_active": "### REQUEST: GET http://127.0.0.1:8930/wp-content/plugins/backup-backup/readme.txt"},
        regex=r"Stable tag:\s*([0-9][0-9A-Za-z.\-]*)", kind="version", product="backup-backup",
        state_notes={"bb137_inactive":
                     "readme capture taken in the 1.3.7 ACTIVE state; deactivation does not modify plugin "
                     "files (registry Appendix F: 'directory untouched'), and the case README §6 lists states "
                     "a/b in one column -> accepted as the E5 artifact for both 1.3.7 states"}),
    ("CVE-2023-6553", "probe_direct_file_reachable"): dict(
        # POST benign (real plugin dir, NO filter chain) -> HTTP 200 + 0-byte body on all
        # three states.  The capture annotates the response as `### RESPONSE 200 (0 bytes)`,
        # so the predicate reads that annotation (there is no `< HTTP/1.1` line in these files).
        file=None, files={"bb137_active": "topup_6553_benign_137_active",
                          "bb137_inactive": "topup_6553_benign_137_inactive",
                          "bb138_active": "topup_6553_benign_138_control"},
        markers={}, regex=r"###\s+RESPONSE\s+(\d{3})\s+\((\d+) bytes?\)", kind="empty_body_200",
        product="backup-backup"),
}

_STATE_ALIAS = {
    # case artifact_state_key -> extractor marker key, when a state reuses a capture
    "rss_9111_2fa_off": "rss_9111_2fa_on",
    "httpd2449_default_249_8081": "httpd2449_default_249_8081",
    "rc143": "rc1411",
    "rc144": "rc1412",
}


def _file_text(key: str) -> str:
    return (REPO / ARTIFACTS[key]).read_text(encoding="utf-8", errors="replace")


def _section(text: str, markers: list, marker: str) -> str:
    """Return the slice of ``text`` belonging to ``marker`` (until the next marker)."""
    if marker in (None, ""):
        return text
    positions = []
    for m in markers:
        if m not in text:
            raise SystemExit(f"section marker not found: {m!r}")
        positions.append((text.index(m), m))
    positions.sort()
    start = text.index(marker)
    end = len(text)
    for pos, m in positions:
        if pos > start:
            end = pos
            break
    return text[start:end]


def _extract(spec: dict, text: str, marker: str, boundaries=None) -> tuple:
    """Return ``(matched_line, value, body)`` or ``(None, None, body)``.

    ``body`` is the (marker-scoped) capture text; the kind handlers use it for the
    probes whose ``true_when`` is a *combination* of the status line and the body
    (e.g. WordPress REST root: 200 **and** JSON ``routes``).

    ``boundaries`` overrides the section end-markers (used by the ``sections`` spec
    key for multi-request captures that are not keyed by ``markers``).
    """
    if boundaries is None:
        boundaries = list((spec.get("markers") or {}).values())
    else:
        # `sections` may key states that live in DIFFERENT capture files; a marker
        # absent from this file cannot bound a section in it.
        boundaries = [b for b in boundaries if b in text]
    body = _section(text, boundaries, marker)
    m = re.search(spec["regex"], body)
    if not m:
        return None, None, body
    line = next((ln.strip() for ln in body.splitlines() if re.search(spec["regex"], ln)), "")
    return line, m.group(1).strip(), body


def build_observations(mapping: dict, cases_doc: dict) -> dict:
    cases = cases_doc["cases"]
    out = {}
    stats = {"verified_probe_requests": 0, "accepted_observations": 0,
             "extra_condition_extractions": 0, "unobserved_entries": 0}
    for case in cases:
        cve, state = case["cve_id"], case.get("artifact_state_key")
        case_obs, unobserved = [], []
        for probe in ((mapping[cve].get("method") or {}).get("probes") or []):
            pid = probe.get("id")
            cond = probe.get("maps_to")
            cond_kind = ((mapping[cve]["reference"]["conditions"].get(cond)) or {}).get("kind")
            validation = probe.get("validation") or {}
            status = validation.get("status")
            spec = VERIFIED_EXTRACTORS.get((cve, pid))
            if status == "verified" and spec:
                sections = spec.get("sections") or {}
                file_key = (spec.get("files") or {}).get(state) or spec.get("file")
                boundaries = None
                if sections:
                    marker = sections.get(state)
                    boundaries = list(sections.values())
                else:
                    marker = (spec.get("markers") or {}).get(
                        (spec.get("files") or {}).get(state, state) if spec.get("file") is None else state)
                    if spec.get("file") is None:
                        marker = None  # whole-file capture
                if marker is None and (spec.get("markers") or sections):
                    # state not covered by this probe's captures
                    unobserved.append(_unobserved(pid, cond, cond_kind, status,
                                                  f"no accepted capture for artifact state {state!r}"))
                    continue
                text = _file_text(file_key)
                line, value, body = _extract(spec, text, marker, boundaries)
                if line is None:
                    raise SystemExit(f"verified probe {cve}/{pid}: pattern {spec['regex']!r} not found for state {state!r}")
                rec = _observation(case, probe, cond, cond_kind, spec, value, line, file_key, marker, body)
                if (spec.get("state_notes") or {}).get(state):
                    rec["artifact_state_note"] = spec["state_notes"][state]
                case_obs.append(rec)
                stats["verified_probe_requests"] += 1
                stats["accepted_observations"] += 1
                # One probe/response may carry more than one mapped condition (R4:
                # 2 extractions = 1 request).  The shared response decides both with
                # the same predicate value; each condition gets its own record.
                for extra in spec.get("also_maps_to") or []:
                    extra_kind = ((mapping[cve]["reference"]["conditions"].get(extra)) or {}).get("kind")
                    case_obs.append(_shared_extraction(rec, extra, extra_kind))
                    stats["accepted_observations"] += 1
                    stats["extra_condition_extractions"] += 1
            else:
                reason = ("G7 gate: probe status is not verified -> no True/False and no E5 value"
                          if status != "verified" else "verified probe not mapped for this case state")
                if status != "verified":
                    reason = f"G7 gate: probe validation.status={status!r} -> Unknown (no accepted capture)"
                unobserved.append(_unobserved(pid, cond, cond_kind, status, reason))
                stats["unobserved_entries"] += 1
        out[case["case_id"]] = {
            "cve_id": cve,
            "artifact_state_key": state,
            "observations": case_obs,
            "unobserved": unobserved,
        }
    return {
        "generated_at_utc": now_utc(),
        "generated_by": "experiments/methods/build_inputs.py (engineer, step 3 phase A)",
        "policy": {
            "source": "only probes with validation.status == 'verified' contribute an observed value (G7)",
            "extraction": "value read from the frozen HTTP capture referenced by the probe (artifact line recorded per observation)",
            "shared_response": "a probe whose single response maps to several conditions emits one record per condition from "
                               "the same extraction (R4: 2 extractions = 1 request), never a second probe/request",
            "excluded_sources": ["PoC/exploit logs", "database state dumps", "attacker listeners", "dpkg -l / installed-package metadata",
                                 "image digests", "tarball/zip sha256"],
            "not_ground_truth": "this file is an INPUT to the methods (observed evidence), not ground truth",
        },
        "counts": stats,
        "cases": out,
    }


def _unobserved(pid, cond, kind, status, reason):
    return {"probe_id": pid, "condition_id": cond, "kind": kind, "validation_status": status, "observed": None, "reason": reason}


def _shared_extraction(primary: dict, extra_cond: str, extra_kind: str) -> dict:
    """Second condition extracted from the *same* response as ``primary`` (R4).

    Copies the artifact provenance of the primary record; only the condition id/kind
    and the reason change.  No extra request is made and no extra probe exists.
    """
    rec = dict(primary)
    rec["condition_id"] = extra_cond
    rec["kind"] = extra_kind
    rec["predicate_reason"] = (f"{primary.get('predicate_reason', '')} — same response as "
                              f"{primary.get('probe_id')} (R4: 2 extractions = 1 request)")
    rec["shared_response_with"] = primary.get("probe_id")
    return rec


def _observation(case, probe, cond, cond_kind, spec, value, line, file_key, marker, body=""):
    kind = spec["kind"]
    rec = {
        "probe_id": probe.get("id"),
        "condition_id": cond,
        "kind": cond_kind,
        "validation_status": "verified",
        "observed": True,
        "artifact_ref": ARTIFACTS[file_key],
        "artifact_section": marker,
        "artifact_line": line,
        "extraction_rule": spec["regex"],
        "value_kind": kind,
    }
    version = None
    version_status = "not_observed"
    predicate = None
    predicate_reason = ""
    if kind == "version":
        version = value
        version_status = "observed" if versioncmp.is_clean_release(value) else "ambiguous"
        if version_status == "observed":
            predicate = True
            predicate_reason = f"observed version token {value!r} at {ARTIFACTS[file_key]}"
        else:
            predicate = None
            predicate_reason = (f"observed token {value!r} is not a clean release (mapping ambiguity_when) -> not used as E5")
        rec["identity_text"] = f"{spec['product']} {value}"
    elif kind == "family":
        predicate = True
        predicate_reason = f"observed product family {value!r}; minor/patch not exposed (mapping note)"
        rec["identity_text"] = value
        version_status = "family_only"
    elif kind == "status200":
        # The mapping's true_when for this probe kind is "HTTP 200 *and* the body
        # JSON carries 'routes'".  The frozen capture records the status only
        # (`GET /wp-json/ -> 200`), so the predicate cannot be decided: True would
        # claim evidence the artifact does not contain.  Review finding 1
        # (Review_buoc3_implementation_2026-10-15.md §1).
        predicate = None   # true_when needs 200 AND body 'routes'; body not captured -> undecided
        predicate_reason = ("HTTP status %s captured, but the mapping true_when also requires body JSON 'routes' "
                            "which is not in the frozen capture -> predicate Unknown" % value)
        rec["limits"] = "artifact records the status only; the JSON body was not captured (predicate cannot be decided -> Unknown)"
    elif kind == "rest_routes":
        # WordPress REST index probe (CVE-2017-1001000.probe_rest_root, D-033/D-034).
        # true_when: HTTP 200 AND the body is the JSON API root carrying `"routes"`.
        # false_when: HTTP 200 but the body is not that JSON (front-page fallback
        #   under plain permalinks) -> REST not reachable as mapped.
        # everything else (404/500/redirect) is the mapping's ambiguity_when -> Unknown.
        has_routes = '"routes"' in body
        if value == "200":
            predicate = bool(has_routes)
            predicate_reason = (f"HTTP 200 and body JSON 'routes' present ({ARTIFACTS[file_key]})" if has_routes
                                else f"HTTP 200 but body has no JSON 'routes' key ({ARTIFACTS[file_key]}) -> REST index not returned")
        else:
            predicate = None
            predicate_reason = f"HTTP {value}: mapping ambiguity_when (REST not exposed / protected / redirected) -> Unknown"
        rec["body_has_routes"] = has_routes
    elif kind == "rest_route_presence":
        # CVE-2024-10924.probe_two_fa_route (D-033/D-034).  A single response decides
        # BOTH mapped conditions (p_2fa_enabled and p_skip_onboarding_route, R4):
        #   400 rest_missing_callback_param -> route registered  -> both True
        #   404 rest_no_route                -> route not present -> both False
        # Anything else is the mapping's ambiguity_when -> Unknown.
        if value == "400" and "rest_missing_callback_param" in body:
            predicate = True
            predicate_reason = ("HTTP 400 rest_missing_callback_param -> the two_fa route is registered, "
                                "so login protection (2FA) is ON and the skip_onboarding route exists")
        elif value == "404" and "rest_no_route" in body:
            predicate = False
            predicate_reason = ("HTTP 404 rest_no_route -> the two_fa route is not registered, "
                                "so login protection (2FA) is OFF and the skip_onboarding route does not exist")
        else:
            predicate = None
            predicate_reason = f"HTTP {value}: mapping ambiguity_when (bare 404 / 401 / 403 / 200) -> Unknown"
    elif kind == "form_markers":
        # CVE-2023-3460.probe_um_register_form (D-034).
        # true_when: HTTP 200 AND body carries `um-form` + `user_login-7` + `_wpnonce`.
        marks = {m: (m in body) for m in ("um-form", "user_login-7", "_wpnonce")}
        if value == "200":
            predicate = all(marks.values())
            predicate_reason = (f"HTTP 200 and registration-form markers present {marks} ({ARTIFACTS[file_key]})" if predicate
                                else f"HTTP 200 but registration-form markers incomplete {marks} -> form not rendered as mapped")
        else:
            predicate = None
            predicate_reason = f"HTTP {value}: mapping ambiguity_when (form page absent or moved) -> Unknown"
        rec["form_markers"] = marks
    elif kind == "php8":
        predicate = value.startswith("8.")
        predicate_reason = f"X-Powered-By: PHP/{value} -> PHP 8 runtime precondition"
        rec["identity_text"] = f"PHP {value}"
    elif kind == "fixture_asset":
        predicate = bool(value) and "ele-custom-skin" in value and "?ver=3.1.3" in value
        predicate_reason = f"fixture asset observed: {value!r}"
        rec["identity_text"] = value or None
    elif kind == "negative_version":
        predicate = None
        predicate_reason = ("negative-observability probe: the capture confirms the plugin version asset is absent; "
                            "the mapping's true_when cannot fire, so p_version_observed stays undecided and E5 remains unknown")
        rec["negative_observability"] = {"version_observable": False, "evidence": line}
    elif kind == "config_disclosure":
        # CVE-2023-23752.probe_config_application_public (mapping top-up, ruling #2/#3).
        # true_when: 200 + JSON:API envelope + data[] attributes carrying the global
        #   JConfig keys (dbprefix, sitename, host, user).  Secret keys are RECORDED but
        #   not required -- the canary VALUE is a label criterion (D-035 §4), not a
        #   method predicate.
        # false_when: 401 + Joomla JSON:API error envelope `{"errors":[{"title":"Forbidden"}]}`
        #   (an app-level denial, not a bare 403/404).
        min_keys = ("dbprefix", "sitename", "host", "user")
        has_keys = {k: (f'"{k}":' in body) for k in min_keys}
        secret_keys = {k: (f'"{k}":' in body) for k in ("password", "secret")}
        envelope_ok = '"data"' in body and "vnd.api+json" in body
        if value == "200":
            predicate = bool(envelope_ok and all(has_keys.values()))
            predicate_reason = (
                f"HTTP 200, JSON:API envelope={envelope_ok}, JConfig keys present {has_keys} "
                f"({ARTIFACTS[file_key]}) -> unauthenticated global-config object read back")
        elif value == "401" and '"errors"' in body and "Forbidden" in body:
            predicate = False
            predicate_reason = ("HTTP 401 + Joomla JSON:API error envelope {\"errors\":[{\"title\":\"Forbidden\"}]} "
                                "-> the resource answers and denies the unauthenticated request (application level)")
        else:
            predicate = None
            predicate_reason = (f"HTTP {value}: mapping ambiguity_when (bare 401/403/404 without the JSON:API envelope, "
                                "HTML fallback, empty data[]) -> Unknown")
        rec["jconfig_min_keys"] = has_keys
        rec["jconfig_secret_keys_present"] = secret_keys
    elif kind == "empty_body_200":
        # CVE-2023-6553.probe_direct_file_reachable (mapping top-up, ruling #5/#7).
        # true_when (measured signal): HTTP 200 with an EMPTY (0-byte) body -> the PHP
        #   file at that exact path executed and discarded its output; the Content-Dir is
        #   the real plugin dir (benign, no filter chain, no marker).
        # No false_when (one-sided, ruling #7): an absent/blocked file is Unknown.  The
        #   negative environment control shows that an absent path here does NOT 404 --
        #   WordPress rewrites it to 200 + the front page, which the mapping lists under
        #   ambiguity_when, so a body/status-only rule must not claim False.
        m = re.search(r"###\s+RESPONSE\s+(\d{3})\s+\((\d+) bytes?\)", body)
        status, nbytes = (m.group(1), int(m.group(2))) if m else (value, None)
        rec["response_bytes"] = nbytes
        if status == "200" and nbytes == 0:
            predicate = True
            predicate_reason = ("HTTP 200 with a 0-byte body -> a PHP file at the exact path executed and discarded "
                                f"its output (benign Content-Dir, no filter chain) ({ARTIFACTS[file_key]})")
        elif status == "200":
            predicate = None
            predicate_reason = (f"HTTP 200 with {nbytes!r} body bytes: mapping ambiguity_when (front-page rewrite / "
                                "non-empty PHP error) -> Unknown")
        else:
            predicate = None
            predicate_reason = f"HTTP {status}: mapping ambiguity_when (file missing OR direct access blocked) -> Unknown"
    rec["version"] = version
    rec["version_status"] = version_status
    rec["predicate_value"] = predicate
    rec["predicate_reason"] = predicate_reason
    return rec


# --------------------------------------------------------------------------- #
# 3. ADVISORY RANGES — normalised from the frozen advisory artifacts
# --------------------------------------------------------------------------- #
APACHE_ENTRY_RE = re.compile(r"(?P<severity>critical|important|moderate|low):\s*(?P<title>.*?)\s*\(\s*(?P<cve>CVE-\d{4}-\d+)\s*\)", re.S)
APACHE_AFFECTS_SENTENCE_RE = re.compile(
    r"This issue only affects Apache\s+(?P<vers>\d+(?:\.\d+)+(?:\s+and\s+Apache\s+\d+(?:\.\d+)+)*)\s+and not earlier versions",
    re.S,
)


def apache_entry_ranges(text: str, cve_id: str) -> dict:
    """Per-entry extraction for the Apache httpd security page.

    The page is one long run of entries of the form

        ``<severity>: <title> ( CVE-... ) <description> ... <reporter block>``

    where a single "Fixed in Apache HTTP Server X" header can cover several
    entries.  The affected versions are taken from the entry's own description
    sentence ("This issue only affects Apache <versions> and not earlier
    versions."), which is entry-scoped and therefore immune to the sibling
    CVE-2021-41773 / CVE-2021-42013 entries sharing one page.
    """
    entries = list(APACHE_ENTRY_RE.finditer(text))
    idx = None
    for i, m in enumerate(entries):
        if m.group("cve") == cve_id:
            idx = i
            break
    if idx is None:
        raise SystemExit(f"apache entry for {cve_id} not found")
    start = entries[idx].start()
    end = entries[idx + 1].start() if idx + 1 < len(entries) else len(text)
    body = text[start:end]
    sentence = APACHE_AFFECTS_SENTENCE_RE.search(body)
    if not sentence:
        raise SystemExit(f"no affected-version sentence for {cve_id}")
    versions = re.findall(r"\d+(?:\.\d+)+", sentence.group("vers"))
    if not versions:
        raise SystemExit(f"no versions parsed for {cve_id}: {sentence.group('vers')!r}")
    return {
        "title": entries[idx].group("title").strip(),
        "ranges": [{"eq": v} for v in versions],
        "quote": sentence.group(0).strip(),
        "sentence_versions": versions,
    }


def manifest_files(snapshot_dir: Path, cve: str) -> dict:
    """The manifest ``files`` block for one CVE (cohort-relative artifact audit)."""
    manifest = json.loads((snapshot_dir / "manifest.json").read_text(encoding="utf-8"))
    return ((manifest.get("artifacts") or {}).get(cve) or {}).get("files") or {}


def cna_affected_from_json(path: Path, cve_id: str) -> dict:
    """Read the machine-readable affected range from a CVE.org 5.x CNA record.

    This is the advisory-only **JSON branch** (mapping top-up ruling #8): a CNA
    record exposes ``containers.cna.affected[].versions[]`` with explicit
    ``lessThan``/``lessThanOrEqual``/``version`` fields, i.e. the advisory range is
    machine-readable without parsing a rendered page.  Only entries with
    ``status == "affected"`` contribute; an empty result aborts the build (missing
    data must never be turned into a range).
    """
    record = json.loads(path.read_text(encoding="utf-8"))
    meta = record.get("cveMetadata") or {}
    if meta.get("cveId") != cve_id:
        raise SystemExit(f"{path}: cveMetadata.cveId={meta.get('cveId')!r} != {cve_id}")
    cna = (record.get("containers") or {}).get("cna") or {}
    ranges, literals = [], []
    for aff in cna.get("affected") or []:
        for v in aff.get("versions") or []:
            if v.get("status") != "affected":
                continue
            if v.get("lessThanOrEqual") is not None:
                rng = {"end_including": v["lessThanOrEqual"]}
                if v.get("version") not in (None, "", "*"):
                    # CVE 5.x uses version "0" as the "no lower bound" convention
                    # (with defaultStatus unaffected); it is kept verbatim so the
                    # encoding is traceable to the record rather than inferred.
                    rng = {"start_including": v["version"], "end_including": v["lessThanOrEqual"]}
                ranges.append(rng)
                literals.append(v)
            elif v.get("lessThan") is not None:
                rng = {"end_excluding": v["lessThan"]}
                if v.get("version") not in (None, "", "*"):
                    rng = {"start_including": v["version"], "end_excluding": v["lessThan"]}
                ranges.append(rng)
                literals.append(v)
    if not ranges:
        raise SystemExit(f"{path}: no status=affected version range found in containers.cna.affected")
    return {
        "record": record,
        "cna": cna,
        "ranges": ranges,
        "literals": literals,
        "title": cna.get("title"),
        "descriptions": [d.get("value") for d in cna.get("descriptions") or [] if d.get("value")],
    }


def build_advisory_ranges() -> dict:
    """Normalised advisory ranges.  ``null`` where the artifact carries no readable range."""
    adv = {}

    def add(cve, file, kind, ranges, quotes, null_reason=None, scope_note=None, extraction=None, negative_quotes=None):
        path = cohort_dir(cve) / cve / file
        text = norm_text(path.read_text(encoding="utf-8", errors="replace"))
        for q in quotes:
            require_quote(text, q, f"{cve}/{file}")
        for q in negative_quotes or []:
            if quote_pattern(q).search(text):
                raise SystemExit(f"NEGATIVE CHECK FAILED in {cve}/{file}: {q!r} unexpectedly present")
        adv[cve] = {
            "artifact": rel_repo(path),
            "artifact_sha256": sha256_file(path),
            "extraction_kind": kind,
            "ranges": ranges,
            "null_reason": null_reason,
            "scope_note": scope_note,
            "quotes": quotes,
            "negative_checks": negative_quotes or [],
            "extraction": extraction,
        }

    add("CVE-2014-3704", "advisory.html", "affected_versions_block",
        [{"line": "7", "end_excluding": "7.32"}],
        ["Drupal core 7.x versions prior to 7.32.", "If you use Drupal 7.x, upgrade to Drupal core 7.32 ."])
    add("CVE-2015-3440", "advisory.html", "fixed_release_statement",
        [{"end_excluding": "4.2.1"}],
        ["WordPress 4.2.1 is now available. This is a critical security release for all previous versions"],
        scope_note="advisory names the fixed release and 'all previous versions'; open lower bound")
    add("CVE-2017-1001000", "advisory.html", "body_sentence",
        [{"eq": "4.7"}, {"eq": "4.7.1"}],
        ["WordPress 4.7 and 4.7.1 had one additional vulnerability for which disclosure was delayed."],
        scope_note="the post has no 'Affected versions' block; the body sentence names the two affected releases explicitly",
        extraction="body sentence naming the affected releases (no formatted block)")
    add("CVE-2018-7600", "advisory.html", "affected_versions_block",
        [{"line": "7", "end_excluding": "7.58"}, {"start_including": "8.0.0", "end_excluding": "8.3.9"},
         {"start_including": "8.4.0", "end_excluding": "8.4.6"}, {"start_including": "8.5.0", "end_excluding": "8.5.1"}],
        [">=7.0 <7.58 || >= 8.0.0 <8.3.9 || >=8.4.0 <8.4.6 || >=8.5.0 <8.5.1"])
    add("CVE-2018-7602", "advisory.html", "affected_versions_block",
        [{"line": "7", "end_excluding": "7.59"}, {"start_including": "8.0.0", "end_excluding": "8.4.8"},
         {"start_including": "8.5.0", "end_excluding": "8.5.3"}],
        [">=7.0 <7.59 || >= 8.0.0 <8.4.8 || >=8.5.0 <8.5.3"])
    add("CVE-2019-6340", "advisory.html", "affected_versions_block",
        [{"start_including": "8.0.0", "end_excluding": "8.5.11"}, {"start_including": "8.6.0", "end_excluding": "8.6.10"}],
        [">= 8.0.0 <8.5.11 || >=8.6.0 <8.6.10"])
    add("CVE-2019-6341", "advisory.html", "affected_versions_block",
        [{"line": "7", "end_excluding": "7.65"}, {"start_including": "8.0.0", "end_excluding": "8.5.14"},
         {"start_including": "8.6.0", "end_excluding": "8.6.13"}],
        [">=7.0 <7.65 || >= 8.0.0 <8.5.14 || >=8.6.0 <8.6.13"])
    add("CVE-2019-8942", "advisory.html", "none", None, [],
        null_reason="saved artifact is the Sonar blog shell of the redirected RIPSTECH page; it does not reference the CVE ID and carries no "
                    "affected/fixed range in the frozen bytes",
        scope_note="spec §4.3 null list")
    add("CVE-2019-10692", "advisory.html", "none", None, [],
        null_reason="saved artifact is the wordpress.org plugin page/changelog, which lists only recent 10.x/2026 releases; the advisory "
                    "release numbers 7.11.17 / 7.11.18 do not occur in the frozen bytes",
        scope_note="mapping open item B7 + spec §4.3 null list",
        extraction="negative check: the strings 7.11.17 and 7.11.18 are asserted absent from the frozen artifact",
        negative_quotes=["7.11.17", "7.11.18"])
    ROUNDCUBE_NEWS_1425 = ["Security updates 1.4.4, 1.3.11 and 1.2.10 released",
                           "We just published service and security updates to the stable version 1.4 and the LTS versions 1.3 and 1.2 of Roundcube Webmail.",
                           "See the full changelogs in the release notes on the Github download pages for the updated versions 1.4.4 , 1.3.11 and 1.2.10 ."]
    for cve, extra in (("CVE-2020-12625", "Cross-Site Scripting (XSS) via malicious HTML content ( CVE-2020-12625 ) **"),
                       ("CVE-2020-12640", "Path traversal vulnerability allowing local file inclusion via crafted"),
                       ("CVE-2020-12641", "Remote code execution via crafted config options ( CVE-2020-12641 ) **")):
        add(cve, "advisory.html", "fixed_version_list",
            [{"line": "1.4", "end_excluding": "1.4.4"}, {"line": "1.3", "end_excluding": "1.3.11"},
             {"line": "1.2", "end_excluding": "1.2.10"}],
            [extra] + ROUNDCUBE_NEWS_1425,
            scope_note="news post lists the fixed releases per line (1.4.4 / 1.3.11 / 1.2.10) without an affected-version block; "
                       "each branch is encoded as a line-scoped range")
    add("CVE-2020-13671", "advisory.html", "affected_versions_block",
        [{"line": "7", "end_excluding": "7.74"}, {"start_including": "8.0.0", "end_excluding": "8.8.11"},
         {"start_including": "8.9.0", "end_excluding": "8.9.9"}, {"start_including": "9.0.0", "end_excluding": "9.0.8"}],
        [">=7.0 <7.74 || >= 8.0.0 <8.8.11 || >= 8.9.0 <8.9.9 || >=9.0.0 <9.0.8"])
    add("CVE-2020-25213", "advisory-fallback.html", "none", None,
        ["6.9 (1st Sept, 2020) Security issue fixed"],
        null_reason="recorded primary URL was bot-blocked; the vendor fallback changelog names the fixed release 6.9 but no affected range",
        scope_note="spec §4.3 null list")
    add("CVE-2021-23017", "advisory.html", "fixed_version_table",
        [{"op": "lt", "version": "1.18.0-6ubuntu9"}],
        ["Fixed 1.18.0-6ubuntu9"],
        scope_note="Ubuntu CVE page states per-release fixed package revisions (no upstream affected range); the observed banner carries "
                   "no package revision, so advisory-only cannot place the target in or out of this distro-build range (R2)")
    add("CVE-2021-24917", "advisory.html", "title_fixed_in",
        [{"end_excluding": "1.9.1"}],
        ["Fixed in 1.9.1"])
    add("CVE-2021-29447", "advisory.html", "affected_versions_block",
        [{"start_including": "5.6", "end_excluding": "5.7.1"}],
        ["Affected versions 5.6 - 5.7", "Patched versions 5.7.1"])
    apache_text = norm_text((cohort_dir("CVE-2021-41773") / "CVE-2021-41773" / "advisory.html").read_text(encoding="utf-8", errors="replace"))
    for cve in ("CVE-2021-41773", "CVE-2021-42013"):
        entry = apache_entry_ranges(apache_text, cve)
        require_quote(apache_text, entry["quote"], f"{cve}/advisory.html")
        adv[cve] = {
            "artifact": rel_repo(cohort_dir(cve) / cve / "advisory.html"),
            "extraction_kind": "affected_versions_block",
            "ranges": entry["ranges"],
            "null_reason": None,
            "scope_note": f"httpd security page entry for {cve} (title/fixed header scoping used to avoid the sibling entry)",
            "quotes": [entry["quote"]],
            "extraction": f"entry-scoped description sentence of the {cve} entry: {entry['sentence_versions']}",
        }
    add("CVE-2021-44026", "advisory.html", "none", None,
        ["Rename session items 'search' and 'search_params' to 'contact_search' and 'contact_search_params'"],
        null_reason="saved artifact is the commit page (diff only); no affected/fixed version statement",
        scope_note="spec §4.3 null list")
    add("CVE-2022-21661", "advisory.html", "body_sentence",
        [{"start_including": "3.7", "end_excluding": "5.8.3"}],
        ["Four security issues affect WordPress versions between 3.7 and 5.8",
         "a SQL injection vulnerability in WP_Query"],
        scope_note="release post states the affected span for the four issues and the fixed release 5.8.3; not per-CVE branched",
        extraction="body sentence (span 3.7–5.8) + fixed release 5.8.3 from the release title")
    add("CVE-2023-2745", "advisory.html", "fixed_release_statement",
        [{"line": "6.2", "end_excluding": "6.2.1", "out_of_scope": "unknown"}],
        ["WordPress 6.2.1 is now available!", "All versions since WordPress 4.1 have also been updated."],
        scope_note="advisory only determines the 6.2 line; other lines are affected per 'since 4.1' but "
                   "with no stated fixed version -> out of 6.2 line = Unknown, no CPE/NVD borrowing. "
                   "The release post names the fixed 6.2.1 for the 6.2 line and says \"All versions since "
                   "WordPress 4.1 have also been updated\", but gives no per-line fixed versions; only the "
                   "6.2 line is precisely encodable, and the range key `out_of_scope: \"unknown\"` makes a "
                   "non-6.2 observed version mechanically Unknown (source does not determine it) instead of "
                   "\"outside the advisory line\" -> Not Applicable (source isolation, review findings 4b + 2745)")
    add("CVE-2023-28121", "advisory.html", "fixed_version_list",
        [{"start_including": "4.8.0", "end_excluding": "4.8.2"}, {"start_including": "4.9.0", "end_excluding": "4.9.1"},
         {"start_including": "5.0.0", "end_excluding": "5.0.4"}, {"start_including": "5.1.0", "end_excluding": "5.1.3"},
         {"start_including": "5.2.0", "end_excluding": "5.2.2"}, {"start_including": "5.3.0", "end_excluding": "5.3.1"},
         {"start_including": "5.4.0", "end_excluding": "5.4.1"}, {"start_including": "5.5.0", "end_excluding": "5.5.2"},
         {"start_including": "5.6.0", "end_excluding": "5.6.2"}],
        ["All websites with WooCommerce Payments 4.8.0 and higher installed and activated on their site",
         "Patched WooCommerce Payments (WooPayments) Versions 4.8.2 4.9.1 5.0.4 5.1.3 5.2.2 5.3.1 5.4.1 5.5.2 5.6.2 5.7.0 6.2.2 6.3.0 6.3.2 6.4.0"],
        extraction="the advisory lists patched versions (4.8.2 / 4.9.1 / 5.0.4 / 5.1.3 / 5.2.2 / 5.3.1 / 5.4.1 / 5.5.2 / "
                   "5.6.2 / 5.7.0 / 6.2.2 / 6.3.0 / 6.3.2 / 6.4.0) with the lower bound \"4.8.0 and higher\"; each patched "
                   "release closes its own branch, so the affected set is the per-branch union [branch_first, patch)",
        scope_note="per-branch union derived from the advisory patched-version list + lower bound 4.8.0 (review finding 4a; "
                   "a single span 4.8.0≤v<5.6.2 would wrongly mark mid-branch patched releases such as 5.5.2 as vulnerable)")
    add("CVE-2023-32243", "advisory.html", "affected_versions_block",
        [{"start_including": "5.4.0", "end_including": "5.7.1"}],
        ["versions >= 5.4.0 and <= 5.7.1", "The described vulnerability was fixed in version 5.7.2"])
    add("CVE-2023-3460", "advisory.html", "title_fixed_in",
        [{"end_excluding": "2.6.7"}],
        ["Fixed in 2.6.7"])
    add("CVE-2023-5631", "advisory.html", "fixed_release_statement",
        [{"start_including": "1.6.0", "end_excluding": "1.6.4"}],
        ["We just published a security update to the version 1.6 of Roundcube Webmail.",
         "We strongly recommend to update all productive installations of Roundcube 1.6.x with this new version."],
        scope_note="the frozen news page only covers the 1.6 line (1.6.4); it does not state the 1.4/1.5 fixed releases, so this range "
                   "cannot cover the 1.4.11 case build — recorded, not repaired (CVE is Unresolved, outside the metric denominator)")
    add("CVE-2023-5798", "advisory.html", "title_fixed_in",
        [{"end_excluding": "1.4.4"}],
        ["Fixed in 1.4.4"])
    add("CVE-2024-10924", "advisory-fallback.html", "none", None,
        ["Security: authentication bypass fix"],
        null_reason="recorded primary URL returned a Cloudflare challenge; the vendor fallback changelog names the fixed release 9.1.2 "
                    "without an affected range",
        scope_note="spec §4.3 null list")
    add("CVE-2024-28000", "advisory.html", "affected_versions_block",
        [{"end_including": "6.3.0.1"}],
        ["WordPress LiteSpeed Cache Plugin <= 6.3.0.1 is vulnerable to a high priority Privilege Escalation",
         "Vulnerable version(s)", "Patched version"],
        extraction="Patchstack database fields: 'Vulnerable version(s)' = 6.3.0.1 and 'Patched version' = 6.4; the flattened page text "
                   "emits the values before their labels, so the range is anchored on the sentence plus the two field labels",
        scope_note="mapping literal 'Vulnerable version(s) 6.3.0.1' / 'Patched version 6.4' reverses the flattened label/value order — "
                   "recorded as a cross-check note, the range itself is unchanged")
    add("CVE-2024-37383", "advisory.html", "fixed_release_statement",
        [{"line": "1.5", "end_excluding": "1.5.7"}],
        ["This is a security update to the stable version 1.5 of Roundcube Webmail.",
         "we recommend to update all productive installations of Roundcube 1.5.x with it"],
        scope_note="release notes cover the 1.5 line; the case build 1.5.6 is inside it (1.6 line kept in CPE only)")
    # ---- top-up cohort 2026-10-17 (D-035) ---------------------------------- #
    add("CVE-2023-23752", "advisory.html", "affected_versions_block",
        [{"start_including": "4.0.0", "end_including": "4.2.7"}],
        ["Versions: 4.0.0-4.2.7",
         "Affected Installs Joomla! CMS versions 4.0.0-4.2.7",
         "Solution Upgrade to version 4.2.8"],
        scope_note="vendor Security Centre announcement [20230201] states the affected span 4.0.0-4.2.7 and the fixed 4.2.8; "
                   "NVD 'affected' (4.0.0-4.2.7) and the NVD/CPE configuration (versionStartIncluding 4.0.0, "
                   "versionEndExcluding 4.2.8) agree with it -> no cross-source conflict for this CVE",
        extraction="vendor header block: 'Versions:' + 'Affected Installs' (inclusive range 4.0.0-4.2.7) + "
                   "'Solution' (fixed release 4.2.8)")
    # CVE-2023-6553: the primary advisory URL (WPScan) was bot-blocked (HTTP 403); the
    # recorded fallback is the CVE.org 5.2 CNA record (Wordfence assigner, PUBLISHED),
    # which is machine-readable JSON.  Ruling #8: parse it as the advisory range.
    adv_6553_dir = cohort_dir("CVE-2023-6553")
    json_6553 = adv_6553_dir / "CVE-2023-6553" / "advisory-fallback.json"
    cna_6553 = cna_affected_from_json(json_6553, "CVE-2023-6553")
    files_6553 = manifest_files(adv_6553_dir, "CVE-2023-6553")
    prim_6553 = files_6553.get("advisory") or {}
    fb_6553 = files_6553.get("advisory_fallback") or {}
    if prim_6553.get("http_status") != 403 or not prim_6553.get("error_body"):
        raise SystemExit("CVE-2023-6553: the manifest no longer records the failed WPScan primary (HTTP 403 + audit body)")
    err_6553 = adv_6553_dir / prim_6553["error_body"]
    if sha256_file(err_6553) != prim_6553.get("error_body_sha256"):
        raise SystemExit("CVE-2023-6553: primary audit body sha256 does not match the manifest")
    if sha256_file(json_6553) != fb_6553.get("sha256"):
        raise SystemExit("CVE-2023-6553: advisory-fallback.json sha256 does not match the manifest")
    desc_6553 = " ".join(cna_6553["descriptions"])
    require_quote(desc_6553, "in all versions up to, and including, 1.3.7", "CVE-2023-6553/advisory-fallback.json")
    adv["CVE-2023-6553"] = {
        "artifact": rel_repo(json_6553),
        "artifact_sha256": sha256_file(json_6553),
        "extraction_kind": "cna_affected_versions_json",
        "ranges": cna_6553["ranges"],
        "null_reason": None,
        "scope_note": "CVE.org 5.x CNA record (assigner Wordfence, state PUBLISHED) is the advisory source: the recorded "
                      "primary URL (WPScan) returned HTTP 403 (bot challenge), Wordfence returned HTTP 202 (Cloudflare, "
                      "0 B).  The record's only affected range is version '0' + lessThanOrEqual '1.3.7' (versionType "
                      "semver, defaultStatus unaffected) => affected = every version up to and including 1.3.7.  The "
                      "record does NOT name a fixed release.",
        "quotes": [cna_6553["title"], cna_6553["descriptions"][0]],
        "negative_checks": [],
        "extraction": "containers.cna.affected[].versions[] filtered to status='affected': "
                      + json.dumps(cna_6553["literals"], ensure_ascii=False),
        "fixed_version_provenance": {
            "fixed_version": "1.3.8",
            "not_in_advisory": "neither the CVE.org CNA record nor the NVD record names a fixed release",
            "source": "the 1.3.8 plugin package itself: readme.txt changelog '= 1.3.8 =' / "
                      "'* [FIX] Patched reported CVE - please upgrade' and the added filterChainFix() guard",
            "workspace_refs": ["experiments/topup-2026-10-17/downloads/bb-1.3.8.zip (sha256 "
                               "f8c98d4696e76a09a8cf7df873ca8017131a53b702bef915bbc2966568574e44)",
                               "experiments/topup-2026-10-17/fix-diff.md §2",
                               "notes/cve-verification-topup-2026-10-17.md §3.2"],
            "note": "provenance only — the fixed release is not used to compute this advisory range (the range is the "
                    "inclusive upper bound 1.3.7 from the CNA record)",
        },
        "primary_failure": {
            "artifact": rel_repo(err_6553),
            "artifact_sha256": sha256_file(err_6553),
            "http_status": prim_6553["http_status"],
            "note": "failed-primary audit body preserved by the snapshot; not an advisory source",
        },
    }
    missing = [c for c in sorted(load_mapping()) if c not in adv]
    if missing:
        raise SystemExit(f"advisory ranges missing for {missing}")
    return {
        "generated_at_utc": now_utc(),
        "generated_by": "experiments/methods/build_inputs.py (engineer, step 3 phase A)",
        "policy": {
            "source": "parsed from the frozen advisory artifact bytes only (D-026 cohort data/public-snapshot/ + "
                      "D-035 cohort data/public-snapshot-2026-10-17/); no live re-fetch",
            "null": "advisory has no machine-readable range -> advisory-only returns Unknown at level 1 (spec §4.3)",
            "no_borrowing": "CPE/NVD ranges are never substituted for an advisory range",
            "quote_check": "every recorded quote is verified verbatim (whitespace-tolerant) against the frozen artifact at build time",
            "json_branch": "CVE-2023-6553's advisory artifact is a CVE.org 5.x CNA JSON record (ruling #8): the range is read "
                           "from containers.cna.affected[].versions[] (status=affected) and the record id is asserted; the "
                           "artifact sha256 is checked against the cohort manifest",
            "spec_null_list": ["CVE-2019-8942", "CVE-2019-10692", "CVE-2021-44026", "CVE-2020-25213", "CVE-2024-10924"],
        },
        "cves": adv,
    }


# --------------------------------------------------------------------------- #
# 4. build + report
# --------------------------------------------------------------------------- #
def build_report(cases_doc, observations, advisory, prev_report=None) -> str:
    lines = []
    lines.append("# Step 3 / Phase A — build report (cases, observations, advisory ranges)\n")
    lines.append(f"Generated: {now_utc()} by `experiments/methods/build_inputs.py`.\n")
    lines.append("## Case enumeration\n")
    c = cases_doc["counts"]
    n_resolved = c["n_unique_cves"] - c["n_unresolved_cves"]
    lines.append(f"- `n_unique_cves` = **{c['n_unique_cves']}** ({n_resolved} resolved + "
                 f"{c['n_unresolved_cves']} Unresolved: {', '.join(c['unresolved_cves'])})")
    lines.append(f"- `n_cases` = **{c['n_cases']}**")
    for label, n in sorted(c["n_labels"].items()):
        lines.append(f"  - {label}: {n}")
    lines.append(f"- cases excluded from the metric denominator (Unresolved): {c['n_cases_excluded_from_metrics']}")
    per_cve = {}
    for case in cases_doc["cases"]:
        per_cve.setdefault(case["cve_id"], []).append(case["ground_truth_label"])
    lines.append("\n## Cases per CVE\n")
    lines.append("| CVE | n_cases | labels |")
    lines.append("|---|---|---|")
    for cve, labels in per_cve.items():
        lines.append(f"| {cve} | {len(labels)} | {', '.join(labels)} |")
    lines.append("\n## Observations\n")
    oc = observations["counts"]
    lines.append(f"- accepted observation records: {oc['accepted_observations']} "
                 f"(from {oc['verified_probe_requests']} verified-probe requests; "
                 f"{oc['extra_condition_extractions']} additional condition(s) extracted from a shared response, R4)")
    lines.append(f"- G7 (pending/needs_control -> Unknown) entries recorded: {oc['unobserved_entries']}")
    n_obs_cases = sum(1 for v in observations["cases"].values() if v["observations"])
    lines.append(f"- cases with at least one accepted observation: {n_obs_cases} / {len(observations['cases'])}")
    lines.append("\n## Advisory ranges\n")
    nulls = [k for k, v in advisory["cves"].items() if not v.get("ranges")]
    lines.append(f"- non-null normalised ranges: {len(advisory['cves']) - len(nulls)}")
    lines.append(f"- null (no machine-readable range): {', '.join(sorted(nulls))}")
    lines.append("\nAll advisory quotes were verified against the frozen artifact bytes at build time.\n")
    return "\n".join(lines)


def artifact_hash_block() -> str:
    """sha256 of the derived inputs **as actually written on disk** (+ the frozen inputs).

    Called after writing, so the recorded digests are those of the real artifacts.
    """
    lines = ["\n## Artifact hashes (sha256 of the files as written)\n", "| artifact | sha256 |", "|---|---|"]
    for name in ("cases.json", "observations.json", "advisory_ranges.json"):
        lines.append(f"| `experiments/methods/data/{name}` | `{sha256_file(DATA_DIR / name)}` |")
    lines.append(f"| `notes/collector-mapping-30cve.md` (D-030, amended D-032/D-033/D-034 + 2026-10-17 top-up = 32 CVE; freeze D-037 pending) | `{sha256_file(MAPPING_PATH)}` |")
    lines.append(f"| `data/public-snapshot/manifest.json` (frozen D-026, 2026-10-11 cohort) | `{sha256_file(SNAPSHOT_DIR / 'manifest.json')}` |")
    lines.append(f"| `data/public-snapshot-2026-10-17/manifest.json` (D-035 top-up cohort) | `{sha256_file(SNAPSHOT_COHORT_2026_10_17 / 'manifest.json')}` |")
    lines.append("\n`generated_at_utc` is embedded in each JSON document, so re-running this script yields a different "
                 "byte hash even when nothing else changes; the documents were compared with `generated_at_utc` "
                 "stripped to establish semantic equality.\n")
    lines.append("This build carries the **2026-10-17 top-up**: 2 mapping blocks merged (CVE-2023-23752, CVE-2023-6553) "
                 "per `reviews/Review_mapping_topup_phanquyet_2026-10-17.md`, the 4 new probes `pending` -> `verified` "
                 "from `experiments/topup-2026-10-17/cases/`, the 2 new advisory ranges (one of them parsed from the "
                 "CVE.org CNA **JSON** record), and 5 new cases (2 Joomla + 3 Backup Migration, D-036). "
                 "`cases.json` gains the 5 cases + counts; `observations.json` gains the new accepted observations; "
                 "`advisory_ranges.json` gains the 2 entries. Nothing from the 30-CVE cohort/V1/V2 outputs changed.\n")
    lines.append("\n### Previous build (V2, 2026-10-16), for traceability\n")
    lines.append("| artifact | sha256 (previous) |")
    lines.append("|---|---|")
    for name, digest in PREVIOUS_BUILD_SHA256.items():
        lines.append(f"| `{name}` | `{digest}` |")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify quotes/counts, write nothing")
    args = ap.parse_args(argv)

    mapping = load_mapping()
    cases_doc = build_cases(mapping)
    observations = build_observations(mapping, cases_doc)
    advisory = build_advisory_ranges()
    payloads = {
        "cases.json": json.dumps(cases_doc, indent=1, ensure_ascii=False),
        "observations.json": json.dumps(observations, indent=1, ensure_ascii=False),
        "advisory_ranges.json": json.dumps(advisory, indent=1, ensure_ascii=False),
    }
    report = build_report(cases_doc, observations, advisory)
    if args.check:
        report += ("\n## Artifact hashes\n\n`--check` writes nothing; run without `--check` to write the derived "
                   "inputs and record their sha256 in this report.\n")
        print(report)
        return 0
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in payloads.items():
        (DATA_DIR / name).write_text(text, encoding="utf-8")
    tails = artifact_hash_block()
    (DATA_DIR / "build-report.md").write_text(report + tails, encoding="utf-8")
    print(tails)
    print(f"\nwrote {DATA_DIR}/cases.json, observations.json, advisory_ranges.json, build-report.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
