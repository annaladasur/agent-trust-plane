# ATP-PUBLISH

Status: Review. Independent review pending.

Acceptance: publish only code related to the Agent Trust Plane described in the deck, with a working fresh-clone path. Destination: annaladasur/agent-trust-plane, initially empty and private. No visibility change authorized.

Allowed files: selected core paths in docs/SOURCE-MANIFEST.txt; root README, LICENSE, Makefile, .gitignore, SECURITY.md, CONTRIBUTING.md; .github/workflows/ci.yml; docs/*.md, docs/source-files.json; scripts/*.py; examples/*.json; tests/*.py; kit/README.md and kit/baseline-worksheet.csv; cluster/Makefile.lab; results/README.md; results/Saved-Log-Recount.json; critic/ATP-PUBLISH.md and validation.json; broker/README.md; experiments/exp2/README.md. Source repository remains unchanged.

Evidence: solid-invention main commit 797acf7; saved log SHA f27ac58c46803f5f07da4f52e9f33340e02521092ddadc350b6b8067e3143dde; source Rego policies and tests; posture overlays; presentation Evidence-Notes.md. Preserve historical counts without simulated inferential fallback. Exclude pilot productivity fixtures, generated summaries, unrelated talks, environment files and signing keys.

Known source limitations: custom Python gateway is not the upstream agentgateway distribution; broker/gateway parse JWT claims without verifying signatures/issuer/audience; development credential fallbacks and unpinned images exist; local state and heuristic classifications are prototypes. Default entry path must not deploy these services. Full Kubernetes lab remains explicit opt-in and is not certified production enforcement.

## CC-1 self-review

- Local OPA 1.14.1: 80/80 policy tests passed. Seven synthetic-input examples evaluate the actual policies, including stale approval, quarantine, missing context and signature refusal.
- Python stdlib suite: 10/10 passed. Includes immutable historical output, explicit harness opt-in, exact source hash/count/interval comparison, malformed records and undefined-policy refusal.
- `make recount`: eight model/posture rows match the deck, including 0/20 Wilson upper bound about 16.1%. No inference or data mutation.
- `scripts/check_package.py`: local Markdown links, Python syntax and credential artifact/pattern scan pass. No private payload directories, signing keys or environment files included.
- 19 YAML files parsed with existing PyYAML 6.0.1; syntax only. Full Kubernetes deployment and broker HTTP integration suite were not run and are not claimed ready.
- `make lab-up` without opt-in refused before deployment. The legacy harness requires explicit acknowledgment, and generated outcomes cannot overwrite the historical log.
- OPA release v1.14.1 and checkout action commit verified against their official GitHub repositories. CI downloads the pinned binary and checks its vendor checksum.
- This is a standalone extraction. No unrelated source-monorepository code, gold files or existing dirty work was modified. No task marked Done; independent CC-2 remains pending.

Fresh staged Git snapshot: `make test`, `make demo`, `make recount` and package checks passed with blank AWS credentials. Inherited whitespace issues were normalized; `git diff --cached --check` and embedded ConfigMap `opa check` pass. The optional harness initially required PyYAML even for help; dependency loading is now delayed so help and opt-in refusal work in the dependency-free environment.

Committed fresh clone (`git clone --no-local --branch demo/ATP-PUBLISH`): all four quickstart/package commands passed; 80 Rego tests, 10 Python tests and seven real policy examples. No source files changed during validation.
