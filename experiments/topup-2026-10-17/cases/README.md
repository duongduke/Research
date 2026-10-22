# Top-up cases (D-035) — build + reproduction, 2026-10-17

Status: **built and reproduced on the lab VM; labels PROPOSED only.** No label here is final,
nothing was added to the registry / selection log / frozen mapping / snapshot, and no HTTP
signal is marked `verified` for the collector mapping.

| Case | Product / versions | States built | Observed outcome | Proposed label |
|---|---|---|---|---|
| [CVE-2023-23752](CVE-2023-23752/README.md) | Joomla! CMS 4.2.7 / 4.2.8 | default config both | 4.2.7: unauth 200 + **real canary DB password + `secret`**; 4.2.8: unauth 401, no canary | 4.2.7 **Applicable** / 4.2.8 **Not Applicable (nhánh a)** |
| [CVE-2023-6553](CVE-2023-6553/README.md) | WP 6.7.1 + Backup Migration 1.3.7 / 1.3.8 | 1.3.7 active; 1.3.7 inactive (files present); 1.3.8 active | marker: a **yes**, b **yes** (installed is enough), c **no** (`Incorrect parameters.`) | a **Applicable** / b **Applicable** / c **Not Applicable (nhánh a)** |

Shared stack (compose, DB init, Joomla installer, state driver, pins): [`_stack/`](_stack/README.md).
`artifact-manifest.sha256` lists every artifact file under `CVE-2023-*/` and `_stack/` with its
sha256 (verify with `sha256sum -c artifact-manifest.sha256` from this directory).

Safety: all published container ports are `127.0.0.1` on the lab VM (`_stack/artifacts/safety-listeners.txt`);
no CGI; the only RCE effect is the in-container marker `/tmp/rq-c1-poc-marker` (removed at the
end; final state = Backup Migration 1.3.8 active).
