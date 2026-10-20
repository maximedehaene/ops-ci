# ops-ci (seed)

Seed for the public repo `ops-ci` (ADR-0018). Published in build plan B04. It must hold no secrets, no hostnames or addresses, and no personal data.

- `scripts/`: deterministic CI checks (risk classifier, also run by the Pi at the pin; script rules; retired phrasings; diff stat; report check)
- `scripts/lib/`: the awk engines of the grep and report checks (POSIX awk, so BSD awk works)
- `checks/old-wording.txt`: retired phrasings; `checks/allowed-domains.txt`: domains that may appear (one per line, with a reason)
- `.github/workflows/ci.yml`: reusable CI (`workflow_call`), no secrets. Inputs: `service`, `ops-ci-ref` (the SHA the caller pins; the workflow fetches the scripts at it), optional `script-globs` and `wording-exclude`. The jobs `rule3-grep`, `old-wording-grep`, `diff-stat` and `report-check` run; the others are stubs
- `.github/workflows/on-main.yml`: reusable push-to-`main` job (provenance, deploy issue with before..after and event-check IDs; no risk classification); the caller passes the opener app secrets
- `templates/service-repo/`: caller workflows each service repo copies, pinned to a full commit SHA of `ops-ci`

GitHub does not run workflows from this subfolder while it sits inside `ops`. In `ci.yml` the four jobs named above run when a caller calls the published file; the other jobs, and everything in `on-main.yml` and the templates, still carry `if: false`.

The published `ops-ci` repo must hold exactly this tree (same files, contents and modes, nothing else at its root). `ops/scripts/check_ops_ci_pin.sh --tree` compares the two tree objects.
