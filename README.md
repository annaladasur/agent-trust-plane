# Agent Trust Plane

Reference code for **From Software Supply Chains to AI Supply Chains: Building Trust into Autonomous Engineering Systems**, Cloud Native Now 2026, Raj Annaladasu.

Start with the policy examples below. They evaluate the actual Rego rules locally, without a cluster, model, cloud account, credentials or calls to external systems. The Kubernetes code is an experimental lab prototype; it is not ready to protect production credentials or repositories.

## Quickstart

Requirements: Python 3.10+, GNU Make and [OPA 1.14.1](https://github.com/open-policy-agent/opa/releases/tag/v1.14.1) on your PATH. Use the official release for your platform, or install OPA through your package manager. No Python packages are needed for this path.

```bash
git clone https://github.com/annaladasur/agent-trust-plane.git
cd agent-trust-plane
make demo
make test
make recount
```

`make demo` checks legitimate work, refusal of an unapproved tainted write, a bound approval, stale approval rejection, memory quarantine and a merge record whose signature has not been verified. It exits nonzero if a decision differs from its expected result. Inputs are readable JSON in [examples/](examples/). This is a policy demonstration, not a live attack against a model or code host.

`make test` runs the inherited Rego suite and the standalone Python checks. `make recount` reads the preserved saved log and prints each model/configuration's numerator, denominator and Wilson 95% interval. It does not run attacks or modify the log.

## What is implemented

| Component | Files | How to use it |
|---|---|---|
| Per-tool permissions and bound approvals | [policies/agent/tools.rego](policies/agent/tools.rego) | Evaluate at a trusted tool gateway; input must come from verified identity/provenance, not the agent |
| Memory quarantine | [policies/agent/memory.rego](policies/agent/memory.rego) | Classify a proposed write before storing/retrieving it |
| Delegation restrictions | [policies/agent/delegation.rego](policies/agent/delegation.rego) | Check which agent roles can delegate to each other |
| Required merge decision | [policies/merge/attestation.rego](policies/merge/attestation.rego) | Run outside the agent after independently verifying a statement's signature |
| Decision-record builder | [attest/](attest/) | Build in-toto statement data; signing requires your own key and Cosign |
| Repository/knowledge access model | [fga/](fga/) | Reference OpenFGA schema and test data; no graph server in the default quickstart |
| Gateway, broker, memory server, specialist agents and Kubernetes manifests | [cluster/](cluster/) and [broker/](broker/) | Experimental lab source; read [known limitations](docs/KNOWN-LIMITATIONS.md) before use |
| Configuration comparison and saved evidence | [experiments/exp2/](experiments/exp2/), [results/](results/) | Inspect the conditions and recount historical records |

The Python `cluster/agentgateway.py` is a custom prototype. It is **not** the upstream `agentgateway` project's v1.5.0 distribution. The high-level talk architecture also includes integrations whose deployment and independent enforcement are not established by these files.

## Follow the talk

- [Architecture and boundaries](docs/ARCHITECTURE.md): issue → agent context → memory/tool decision → proposed change → merge check.
- [Evidence and slide 9](docs/EVIDENCE.md): four configurations, exact saved-log location and interpretation limits.
- [Adoption kit](kit/README.md): evaluate one workflow, assign owners and measure useful completion alongside refusals.
- [Experimental Kubernetes lab](docs/LAB.md): prerequisites, setup, validation and cleanup.
- [Contribution guide](CONTRIBUTING.md) and [security limitations](SECURITY.md).

## Educational and authorized use

Examples are for education and defensive security research. Test attack scenarios only on systems you own or are explicitly authorized to assess, within the agreed scope. Use dummy canaries, never customer data or live credentials. The recordings associated with the talk are illustrative reconstructions. Saved-log counts are not a production security guarantee, certification, or a measured benefit from the taint rule alone. Views are the author's own.

Apache-2.0. See [LICENSE](LICENSE). Source extraction and validation are recorded in [docs/PROVENANCE.md](docs/PROVENANCE.md).
