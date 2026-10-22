# Batch 0 stack — deployment & reproduction (RQ-C1 26-CVE build)

> Date: 2026-10-10. VM `<lab-user>@<lab-ip>` (Ubuntu 24.04.5 LTS, Docker 29.8.2,
> Compose v5.6.0). Scope: **Batch 0 only** (5 de-risk cases). Loopback only; no CGI;
> RCE payload = harmless marker only. Deploy dir on the VM: `~/batch0-lab`.

This folder holds the **shared** stack for the three WordPress-core cases
(CVE-2019-8942, CVE-2021-29447, CVE-2022-21661). The nginx case has its own
compose under `../CVE-2021-23017/`. Per-case notes/labels are in `../CVE-*/README.md`.

## Layout

```
_batch0-stack/
  compose/docker-compose.yml           # 6 WP instances + shared MariaDB + XXE attacker listener
  compose/db-init/01-init.sql          # databases + lab user
  compose/apache/extra-port.conf       # Listen 8111 for the CVE-2019-8942 containers
  scripts/10-wp-install.sh             # install WP + author accounts + fixture plugin
  scripts/90-http-observations.sh      # method-visible HTTP observations (pre-PoC)
  scripts/95-capture-artifacts.sh      # end-to-end reproduction capture
  scripts/repro/42-cve-2019-8942.py    # CVE-2019-8942 exploit (marker-only)
  scripts/repro/43-cve-2021-29447.sh   # CVE-2021-29447 XXE
  scripts/repro/44-cve-2022-21661.sh   # CVE-2022-21661 SQLi
  scripts/repro/gen-wav.py             # builds the malicious WAV
  scripts/repro/gen-8942-image.py      # extracts the Metasploit crafted JPEG
  releases/                            # pinned payloads (hashes below)
  attacker/evil.dtd                    # XXE DTD served by the attacker listener
  artifacts/                           # HTTP observations + safety proof
```

## Pinned artifacts (sha256)

| Artifact | sha256 | Source |
|---|---|---|
| `releases/ele-custom-skin.3.1.3.zip` | `5c490eaaa9ec1777fddbc9551633f57e08e154c8754cc7f36e3349295318e978` | `downloads.wordpress.org/plugin/ele-custom-skin.3.1.3.zip` |
| `releases/payload-8942.jpg` | `890f97ba4b465ebebea47dd992ce6f211c845fa5a7445aa780d1452f4699d464` | extracted from Metasploit `modules/exploits/multi/http/wp_crop_rce.rb` |

## Image digests

| Service | Image | Digest |
|---|---|---|
| db | mariadb:10.11 | `mariadb@sha256:7db29378d4fdab73f8123bbc2b48905c90d1a4b00cf848b028f1e81e623257f2` |
| wp-8942-vuln | wordpress:5.0.0-apache | `wordpress@sha256:871ae0ebe72e7eef309bf2b2b9a33ddaba19410a0b3b487b83a7b0252681659a` |
| wp-8942-fixed | wordpress:5.0.1-apache | `wordpress@sha256:33da10a3c3fbf52a815612c9a3688d020b4c3ebcd5c6dff4dbe9ae55bed6cd5b` |
| wp-29447-vuln | wordpress:5.7.0-php8.0-apache | `wordpress@sha256:0632e5687c1365d635e38a850456349972b3f8e8f039a98f6453e3115340b131` |
| wp-29447-fixed | wordpress:5.7.1-php8.0-apache | `wordpress@sha256:fb3de10a201997be88ef562fe470552334acef18ca92a01873cdd0ee821aa014` |
| wp-21661-vuln | wordpress:5.8.2-apache | `wordpress@sha256:fc33b796b04162a0db2e9ea9b4c361a07058b21597b1317ad9ab3ea4593de241` |
| wp-21661-fixed | wordpress:5.8.3-apache | `wordpress@sha256:70246a8dc8282bbe4f9d53d3e88f4b0a2287cdb84b8da356d8bf44542ae14f2d` |
| attacker | python:3.12-alpine | `python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4` |
| nginx (case 5) | built from ubuntu 22.04 | base `ubuntu@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401` |

## Published ports (all `127.0.0.1` — verified with `ss -tlnp`)

| Port | Service | Case |
|---|---|---|
| 13307 | MariaDB | shared |
| 8111 / 8112 | WP 5.0.0 / 5.0.1 | CVE-2019-8942 |
| 8121 / 8122 | WP 5.7.0-php8 / 5.7.1-php8 | CVE-2021-29447 |
| 8131 / 8132 | WP 5.8.2 / 5.8.3 | CVE-2022-21661 |
| 8199 | XXE attacker HTTP listener | CVE-2021-29447 |
| 8190 | nginx jammy | CVE-2021-23017 |

## Reproduce (exact commands, from the lab VM)

```bash
mkdir -p ~/batch0-lab/{wordpress/{8942-vuln,8942-fixed,29447-vuln,29447-fixed,21661-vuln,21661-fixed},releases,attacker,artifacts,apache}
# copy compose/docker-compose.yml -> ~/batch0-lab/docker-compose.yml
# copy compose/db-init -> ~/batch0-lab/db-init ; compose/apache -> ~/batch0-lab/apache
# copy scripts -> ~/batch0-lab/scripts ; releases -> ~/batch0-lab/releases
cd ~/batch0-lab && docker compose up -d
bash scripts/10-wp-install.sh          # builds WP + author + fixture (ground truth)
bash scripts/90-http-observations.sh   # method-visible HTTP signals (pre-PoC)
bash scripts/95-capture-artifacts.sh   # runs the 3 WP reproductions
# nginx case:
cd nginx23017 && docker compose build && docker compose up -d
```

Lab-internal credentials only: `admin/<lab-admin-pass>`, `author/<lab-author-pass>`,
`labuser/<lab-db-pass>`, MariaDB root `<lab-root-pass>`. The VM SSH password is **not** written here.

## Reset between runs

`docker compose down -v` + clear the app bind dirs (`wordpress/*`, recreated empty) +
`up -d` + `scripts/10-wp-install.sh`. The RCE/XXE markers and planted theme files are
removed by `scripts/95-capture-artifacts.sh` before each run.

## Safety

- Every published port is loopback (`ss -tlnp`, `artifacts/safety-loopback-nocgi.txt`).
- Apache has **no `cgi`/`cgid` module** (checked via `a2query -m cgi`).
- RCE executes only `echo RQ-C1-POC-MARKER > /tmp/rq-c1-poc-marker`; XXE exfiltrates
  only our own controlled marker file — no system-file reads, no shell session, no escalation.
