# Top-up cohort 2026-10-17 — step-1 verification evidence (CVE-2023-23752, CVE-2023-6553)

This directory is a **durable copy of the step-1 verification evidence only** — the
advisory/NVD/CVE.org records and the two affected/fixed release pairs (Joomla! 4.2.7
and 4.2.8; Backup Migration 1.3.7 and 1.3.8) — for the two top-up CVEs accepted in
**D-035** (`context/DECISIONS.md`). It is **not ground truth**: **no label** has been
assigned to either CVE, nothing was built or exploited, no container or web installer
was run, and no HTTP request was sent, so nothing here supports an Applicable /
Not Applicable judgement (D-010 requires reproduction for that). The files are
**read-only evidence** with recorded provenance (`manifest.md`: source URL, fetch
date, HTTP status, bytes, sha256 — the four downloads' hashes were re-computed after
copying and all matched the step-1 report), the code-level mechanism summary is in
`fix-diff.md` (KNOWN vs ASSUMED, quoted from these exact packages), and the cohort is
kept **separate** from the 2026-10-11 `data/public-snapshot/` per D-035 §5 — no
frozen artifact, benchmark output, mapping, label or context decision was modified.
