"""versioncmp.py — version parsing / range matching for RQ-C1 step 3 (D-026/D-030).

Pure functions, no I/O. Used by ``methods.py`` and by the synthetic fixture.

Comparison modes (decision recorded in ``experiments/methods/README.md``):

* ``release`` (default; CPE ``versionStart*/versionEnd*`` and advisory ``(op, version)``):
  numeric dotted-release comparison.  ``5.0`` == ``5.0.0`` (missing components are
  zero) and ``1.10`` > ``1.9``.
* ``semver``: same ordering plus SemVer pre-release precedence (``1.0-rc1`` < ``1.0``).
* ``lex``: plain string comparison (only where a source declares a lexicographic
  ordering; not used by any of the five methods in this benchmark).

Suffix rule (release/semver modes).  A suffix is either

* a *pre-release* tag (``-rc1``, ``-beta2``, ``-src``, ...) -> lower precedence than
  the plain release, or
* a *packaging/distro revision* (``-6ubuntu9``, ``-1``, ``-2.el9``, ...) -> higher
  precedence than the plain release.

Scope rule.  A bare upstream version and a distro-revisioned version are **not**
comparable (``1.18.0`` vs ``1.18.0-6ubuntu9``): range matching returns ``None``
("scope mismatch") instead of guessing.  This makes R2 mechanical — knowing the
distro shipped a fixed *package revision* is not knowing the target runs it, and
the banner does not confirm the revision.
"""

from __future__ import annotations

import re

PRERELEASE_WORDS = (
    "rc",
    "beta",
    "alpha",
    "dev",
    "snapshot",
    "src",
    "pre",
    "milestone",
)
DISTRO_REVISION_RE = re.compile(r"^(\d+)(ubuntu|deb|el|fc|suse|bpo|ppa)", re.I)

_TOKEN_RE = re.compile(r"^\d+(\.\d+)*$")


def parse_version(text: str) -> dict:
    """Parse a version token.

    Returns ``{"raw", "release": tuple[int, ...], "suffix", "suffix_kind", "clean"}``
    where ``clean`` marks a strict dotted-release token (no suffix) — the only kind
    of token that may be compared by exact equality with a CPE/version literal
    without guessing.
    """
    raw = (text or "").strip()
    m = re.search(r"\d[\w.*+~-]*", raw)
    core = m.group(0) if m else raw
    head, _, suffix = core.partition("-")
    if not suffix:
        suffix = None
    release: list[int] = []
    inline_suffix: list[str] = []
    for part in re.split(r"[._+~]", head):
        if part == "":
            continue
        if part.isdigit():
            release.append(int(part))
        else:
            inline_suffix.append(part)
    if not suffix and inline_suffix:
        suffix = ".".join(inline_suffix)
    suffix_kind = None
    if suffix:
        suf = suffix.lstrip(".-+~")
        low = suf.lower()
        if any(low.startswith(w) and (len(low) == len(w) or not low[len(w)].isdigit()) for w in PRERELEASE_WORDS):
            suffix_kind = "prerelease"
        elif re.match(r"^(a|b|rc|beta|alpha|dev|pre|milestone)\d*$", low):
            suffix_kind = "prerelease"
        elif DISTRO_REVISION_RE.match(suf):
            suffix_kind = "revision"
        else:
            suffix_kind = "revision"
    return {
        "raw": raw,
        "release": tuple(release),
        "suffix": suffix,
        "suffix_kind": suffix_kind,
        "clean": bool(_TOKEN_RE.match(core)),
    }


def _pad(a: tuple, b: tuple) -> tuple:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def scope_mismatch(a: str, b: str) -> bool:
    """True when ``a``/``b`` differ only by a *distro-revision* suffix (not comparable)."""
    pa, pb = parse_version(a), parse_version(b)
    if pa["release"] != pb["release"]:
        return False
    rev_a = pa["suffix_kind"] == "revision"
    rev_b = pb["suffix_kind"] == "revision"
    return rev_a != rev_b


def cmp_versions(a: str, b: str, mode: str = "release") -> int:
    """Compare version strings. Returns -1 / 0 / 1. Raises on empty input."""
    if not (a or "").strip() or not (b or "").strip():
        raise ValueError("cmp_versions: empty version string")
    if mode == "lex":
        return (a > b) - (a < b)
    pa, pb = parse_version(a), parse_version(b)
    ra, rb = _pad(pa["release"], pb["release"])
    if ra != rb:
        return (ra > rb) - (ra < rb)
    sa, sb = pa["suffix"], pb["suffix"]
    if sa is None and sb is None:
        return 0
    kind = pa["suffix_kind"] if pa["suffix_kind"] == "prerelease" or pb["suffix_kind"] == "revision" else pb["suffix_kind"]
    if kind == "prerelease":
        if sa is None:
            return 1
        if sb is None:
            return -1
    else:  # revision-like suffix sorts *after* the plain release
        if sa is None:
            return -1
        if sb is None:
            return 1
    return (sa > sb) - (sa < sb)


def compare_op(v: str, op: str, bound: str, mode: str = "release"):
    """Evaluate ``v <op> bound`` -> True/False/None (None = not comparable)."""
    if scope_mismatch(v, bound):
        return None
    c = cmp_versions(v, bound, mode)
    return {"lt": c < 0, "le": c <= 0, "gt": c > 0, "ge": c >= 0, "eq": c == 0, "ne": c != 0}[op]


# --------------------------------------------------------------------------- #
# Range model
#
# A *range dict* is the single normalised form used for both CPE and advisory
# bounds. Supported keys:
#   {"op": "lt"|"le"|"gt"|"ge"|"eq", "version": "..."}          -- single bound
#   {"start_including"|"start_excluding"|"end_including"|"end_excluding": "..."}
#   {"line": "1.4", ...}     -- line-scoped: only versions whose release prefix
#                               equals the named line are in scope
#   {"line": "6.2", ..., "out_of_scope": "unknown"}
#                            -- line-scoped for a *partial-scope* advisory: the
#                               source only determines the named line, so a version
#                               on any other line is **not decided** -> ``None``
#                               (Unknown), never ``False``.  Without this key a
#                               line mismatch stays ``False`` (multi-line ranges are
#                               complete enumerations: out-of-line = not affected).
#   {"eq": "5.0", "strict_exact": True}
# Unknown result => the pair is not comparable (scope mismatch / ambiguous token).
# --------------------------------------------------------------------------- #


def normalise_cpe_entry(entry: dict) -> dict:
    """Convert a raw CPE match entry (``cpe.json``/NVD ``criteria``) to a range dict."""
    name = entry.get("cpeName") or entry.get("criteria") or ""
    parts = name.split(":")
    rng: dict = {}
    version = parts[5] if len(parts) > 5 else "*"
    has_range = any(
        entry.get(k) is not None
        for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
    )
    if not has_range and version not in ("*", "-", ""):
        rng["eq"] = version
        rng["strict_exact"] = True
    for key, label in (
        ("versionStartIncluding", "start_including"),
        ("versionStartExcluding", "start_excluding"),
        ("versionEndIncluding", "end_including"),
        ("versionEndExcluding", "end_excluding"),
    ):
        if entry.get(key) is not None:
            rng[label] = entry[key]
    return rng


def match_range(observed: str, rng: dict) -> tuple:
    """Match one observed version against one range dict -> ``(bool|None, reason)``."""
    if not rng:
        return None, "empty range (no version bound)"
    checks: list[tuple[str, object]] = []
    if rng.get("line") is not None:
        line_parts = parse_version(rng["line"])["release"]
        obs_parts = parse_version(observed)["release"][: len(line_parts)]
        same = obs_parts == line_parts
        checks.append((f"line {rng['line']}", same))
        if not same:
            if rng.get("out_of_scope") == "unknown":
                # Partial-scope advisory: the source only determines the named line
                # (e.g. CVE-2023-2745 names the fixed 6.2.1 for the 6.2 line while
                # other lines are said to be "also updated" without a stated fixed
                # version).  Out-of-line is therefore *not determined* -> Unknown.
                return None, (f"observed {observed} is outside the advisory-defined line {rng['line']} "
                              f"(source does not determine it -> Unknown)")
            return False, f"observed {observed} is outside advisory line {rng['line']}"
    if rng.get("eq") is not None:
        bound = rng["eq"]
        if rng.get("strict_exact"):
            po, pb = parse_version(observed), parse_version(bound)
            ok = bool(po["clean"]) and bool(pb["clean"]) and po["release"] == pb["release"]
            checks.append((f"exact {bound}", ok))
        else:
            checks.append((f"eq {bound}", compare_op(observed, "eq", bound)))
    if rng.get("op") is not None:
        checks.append((f"{rng['op']} {rng['version']}", compare_op(observed, rng["op"], rng["version"])))
    for key, op in (
        ("start_including", "ge"),
        ("start_excluding", "gt"),
        ("end_including", "le"),
        ("end_excluding", "lt"),
    ):
        if rng.get(key) is not None:
            checks.append((f"{key} {rng[key]}", compare_op(observed, op, rng[key])))
    unknown = [k for k, r in checks if r is None]
    if unknown:
        return None, f"not comparable at bound(s) {unknown} (range {rng})"
    ok = all(bool(r) for _, r in checks)
    return ok, f"{rng} -> {[(k, bool(r)) for k, r in checks]}"


def match_ranges(observed: str, ranges: list) -> tuple:
    """Union-of-branches match -> ``(bool|None, reasons)``.

    ``True`` if any branch matches; ``False`` only if no branch matched and every
    branch was decidable; ``None`` if nothing matched and a branch was undecidable.
    """
    reasons = []
    any_true = False
    any_unknown = False
    for rng in ranges or []:
        ok, why = match_range(observed, rng)
        reasons.append(why)
        if ok is True:
            any_true = True
        elif ok is None:
            any_unknown = True
    if any_true:
        return True, reasons
    if any_unknown:
        return None, reasons
    return False, reasons


def match_cpe_entry(observed: str, entry: dict) -> tuple:
    """Convenience wrapper: raw CPE entry -> ``(bool|None, reason)``."""
    return match_range(observed, normalise_cpe_entry(entry))


def is_clean_release(text: str) -> bool:
    return bool(text) and bool(parse_version(text)["clean"])
