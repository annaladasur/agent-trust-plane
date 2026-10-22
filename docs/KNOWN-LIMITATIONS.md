# Known implementation limits

The quickstart evaluates actual Rego against explicit fixtures. It does not authenticate users, execute a model, write to a repository, or verify a real signature.

The inherited Kubernetes prototype has material limits:

1. The broker and gateway decode JWT payloads without validating signature, issuer or audience. An identity-looking string is not proof of workload identity. A production implementation needs a proper verifier or Kubernetes TokenReview with audience and principal binding.
2. Development identity/token fallbacks and example database passwords exist. Generating Gitea credentials does not repair the identity-verification issue. Restrict the entire lab to synthetic data and a disposable, isolated environment.
3. The gateway is custom Python HTTP code. CEL-style allowlists and parts of namespace authorization are implemented as Python checks; this is not evidence of upstream agentgateway, CEL or OpenFGA integration compliance.
4. Ledger and decision state are process-local, and trust classification uses heuristics/static maintainer data. Durability, authenticated provenance, policy availability, mandatory routing, ingress authentication and bypass resistance need engineering and validation.
5. Some image tags float; manifests embed copies of Python/Rego. Configuration can drift. The setup assumes Docker Desktop/host.docker.internal, existing images and a working local Ollama endpoint. No fresh Kubernetes deployment was certified for this release.
6. The matrix runner assigns outcomes in posture-specific code, including in its model path; dry-run also creates simulated outcomes. Neither path alone independently measures runtime control efficacy. The generated inferential-analysis pipeline and pilot productivity fixtures are excluded from this standalone release.
7. A merge-policy input saying signature_verified=true must be set only by a trusted external verifier. Never accept it from an agent or an unverified record. Signing keys are intentionally not shipped.

`make lab-up` requires explicit opt-in. Keep the local kind ports and services inaccessible to other users and networks. Remove the lab with `make lab-down` when finished.
