# Evaluate one agent workflow

1. **Scope:** identify the repository, allowed actions, trusted owner and credentials. Record which inputs are public or otherwise untrusted.
2. **Observe:** collect source/tool/decision references without initially blocking legitimate work. Establish a denominator for observed calls and tasks.
3. **Constrain:** evaluate per-tool policy outside the model; quarantine untrusted memory. Require a human approval bound to the task, tool and canonical argument hash for consequential writes.
4. **Verify:** bind a decision record to the current PR revision; independently verify its signature and enforce the required merge check.
5. **Decide:** compare unsafe actions with legitimate completion, approval burden, latency and refusal reasons. Expand only with an owner, a rollback path and evidence that useful work continues.

Use the [baseline worksheet](baseline-worksheet.csv), [reference architecture](../docs/ARCHITECTURE.md), [policy examples](../examples/) and [limitations](../docs/KNOWN-LIMITATIONS.md). The worksheet starts blank; suggested targets are decisions for your organization, not measured results from this repository. A zero-denominator rate is n/a. Report numerator/denominator and uncertainty for small samples.

The offline examples are an entry point for policy evaluation. They do not establish a deployable enterprise security boundary or certify compliance.
