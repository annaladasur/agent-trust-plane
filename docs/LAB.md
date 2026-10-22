# Experimental Kubernetes lab

Use `make demo` first. The cluster source is included so engineers can inspect and develop the reference design; this release has not certified a fresh full-stack cluster deployment. Do not connect it to real repositories or sensitive data. Read [known limitations](KNOWN-LIMITATIONS.md) first, particularly the JWT verification gap.

## Prerequisites

- Docker Desktop with an isolated disposable environment, kind, kubectl, Python 3.10+, GNU Make.
- PyYAML for the legacy matrix harness (install into a virtual environment if using it).
- Local Ollama and an available model if exercising model inference; the original lab used `qwen3-coder:30b` and `qwen3.6:27b`. Their names do not guarantee availability or fit on your machine.
- Cosign and a locally generated signing key if exercising signing; verify the associated public key out of band. Example `cosign.pub` files are historical fixtures, not a trust anchor for your deployment.

`cluster/kind.yaml` creates the local cluster `atp` and reserves localhost-facing ports 3030 (Gitea), 18080 (gateway), 16686 (Jaeger) and 3000. Inspect Docker/kind network exposure before starting. The prototype expects `host.docker.internal` for Ollama and can require changes on Linux.

```bash
# Run only after reading the limitations and reserving a disposable environment.
ATP_UNSAFE_LAB=1 make lab-up
# After inspecting pod health, generated credentials, model reachability and keys:
ATP_UNSAFE_LAB=1 make lab-g0
# Delete this lab's kind cluster when finished:
make lab-down
```

`lab-up` creates Gitea users, synthetic repositories and local secrets, deploys manifests, and configures branch protection in that synthetic Gitea instance. Passwords are generated into ignored `cluster/.gitea.env`. It can take several minutes, pull images and require manual compatibility fixes. The cluster name is fixed to `atp`; do not run it where a valuable cluster has that name. Cleanup destroys that cluster and its disposable data.

Check `kubectl get pods -A`, `kubectl -n agents logs deploy/agentgateway`, and `kubectl -n gitea logs deploy/gitea` on failure. Resolve the specific error; a healthy pod alone is not proof of identity, authorization, signature verification or mandatory routing.

The prototype matrix runner has additional outcome-assignment limitations. See [experiments/exp2/README.md](../experiments/exp2/README.md). Its generated output is kept separate from the historical log. Never label those outputs as verified live enforcement measurements.
