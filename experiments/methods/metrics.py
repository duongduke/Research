"""metrics.py — evaluation metrics for RQ-C1 step 3 (D-026 / D-027 R5).

Unit of evaluation = **case** ``(product, build, config, CVE, access scope)``.
Ground-truth labels are attached only here, *after* prediction (label isolation).

Confusion (only cases with a determined ground-truth label):

======================  =============  ================  =======
GT \\ prediction       Applicable     Not Applicable    Unknown
======================  =============  ================  =======
Applicable              TP             FN_def            U_A
Not Applicable          FP             TN                U_N
======================  =============  ================  =======

Formulas (D-026 / D-027):

* ``N = TP + FP + TN + FN_def + U_A + U_N``
* ``precision = TP / (TP + FP)``
* ``recall    = TP / (TP + FN_def + U_A)``      (U_A stays in the denominator)
* ``F1        = 2·TP / (2·TP + FP + FN_def + U_A)`` (U_A stays; 0 when TP = 0 and denominator > 0)
* ``coverage  = (TP + FP + TN + FN_def) / N``
* ``Unknown rate = (U_A + U_N) / N``

A zero denominator reports ``"N/A"``.  Cases whose ground-truth label is
``Unresolved`` are excluded from ``N`` and reported separately.
"""

from __future__ import annotations

NA = "N/A"
LABELS = ("Applicable", "Not Applicable")
PREDICTIONS = ("Applicable", "Not Applicable", "Unknown")


def _ratio(num: int, den: int):
    return NA if den == 0 else num / den


def confusion(predictions: dict, cases: list, label_key: str = "ground_truth_label") -> dict:
    """Confusion counts for one method. ``predictions`` maps case_id -> prediction."""
    conf = {"TP": 0, "FP": 0, "TN": 0, "FN_def": 0, "U_A": 0, "U_N": 0}
    detail = {k: [] for k in ("TP", "FP", "TN", "FN_def", "U_A", "U_N")}
    excluded = []
    for case in cases:
        label = case.get(label_key)
        cid = case["case_id"]
        if label not in LABELS:
            excluded.append({"case_id": cid, "cve_id": case["cve_id"], "ground_truth_label": label, "reason": "label outside the metric denominator (Unresolved)"})
            continue
        pred = predictions.get(cid)
        if pred not in PREDICTIONS:
            raise ValueError(f"case {cid}: prediction {pred!r} is not one of {PREDICTIONS}")
        if label == "Applicable":
            key = {"Applicable": "TP", "Not Applicable": "FN_def", "Unknown": "U_A"}[pred]
        else:
            key = {"Applicable": "FP", "Not Applicable": "TN", "Unknown": "U_N"}[pred]
        conf[key] += 1
        detail[key].append(cid)
    return {"confusion": conf, "case_ids": detail, "excluded": excluded}


def scores(conf: dict) -> dict:
    tp, fp, tn, fnd, ua, un = (conf[k] for k in ("TP", "FP", "TN", "FN_def", "U_A", "U_N"))
    n = tp + fp + tn + fnd + ua + un
    f1_den = 2 * tp + fp + fnd + ua
    return {
        "N": n,
        "n_determined": tp + fp + tn + fnd,
        "n_abstained": ua + un,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fnd + ua),
        "F1": (NA if f1_den == 0 else (0.0 if tp == 0 else 2 * tp / f1_den)),
        "coverage": _ratio(tp + fp + tn + fnd, n),
        "unknown_rate": _ratio(ua + un, n),
    }


def predicted_vector(predictions: dict, cases: list) -> tuple:
    return tuple(predictions.get(c["case_id"]) for c in cases)


def duplicate_vectors(per_method_predictions: dict, cases: list) -> list:
    """Report identical prediction vectors (CPE≈NVD≈HTTP at level 1) — never hide them."""
    seen = {}
    for method, preds in per_method_predictions.items():
        vec = predicted_vector(preds, cases)
        seen.setdefault(vec, []).append(method)
    return [sorted(v) for v in seen.values() if len(v) > 1]


def label_histogram(cases: list, label_key: str = "ground_truth_label") -> dict:
    hist = {}
    for case in cases:
        hist[case.get(label_key)] = hist.get(case.get(label_key), 0) + 1
    return hist


def evaluate(per_method_predictions: dict, cases: list, groups: dict = None) -> dict:
    """Full metrics block.

    ``per_method_predictions`` = ``{method: {case_id: prediction}}``.
    ``groups`` = ``{group_name: [case_id, ...]}`` (e.g. development-use groups).
    """
    groups = groups or {}
    out = {
        "unit": "case",
        "labels_attached_after_prediction": True,
        "n_unique_cves": len({c["cve_id"] for c in cases}),
        "n_cases": len(cases),
        "n_labels": label_histogram(cases),
        "duplicate_prediction_vectors": duplicate_vectors(per_method_predictions, cases),
        "methods": {},
    }
    by_id = {c["case_id"]: c for c in cases}
    for method, preds in per_method_predictions.items():
        block = confusion(preds, cases)
        entry = {
            "confusion": block["confusion"],
            "scores": scores(block["confusion"]),
            "excluded_unresolved": block["excluded"],
            "case_ids": block["case_ids"],
        }
        if groups:
            entry["by_group"] = {}
            for gname, ids in groups.items():
                gcases = [by_id[i] for i in ids if i in by_id]
                gblock = confusion(preds, gcases)
                entry["by_group"][gname] = {"n_cases": len(gcases), "confusion": gblock["confusion"], "scores": scores(gblock["confusion"])}
        out["methods"][method] = entry
    return out
