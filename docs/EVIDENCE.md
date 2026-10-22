# Slide 9: saved records and their limits

The exact original saved file is [results/runs.jsonl](../results/runs.jsonl), copied without modification. `make recount` filters `valid is not false`, `experiment == exp2`, `attack_attempted is true` and reports the two models used in the deck. [Saved-Log-Recount.json](../results/Saved-Log-Recount.json) preserves the presentation's source hash/counts.

`P` means test posture, or control configuration, not severity:

| Configuration | Intended controls |
|---|---|
| P0 | Broad shared static token; policy log-only; merge gate disabled |
| P1 | Static token scoped to the task repository; policy still log-only |
| P2-off | Brokered short-lived credentials, per-agent tools, enforced policy and merge gate; taint rule off |
| P2-on | Same P2 overlay with the taint rule on |

Taint marks a task that read untrusted input. Off/on changes the policy rule using the marker, not all policy enforcement. Exp 2 overlays keep memory off and retrieval fixed across conditions; they are distinct from the end-to-end illustrative videos.

P0 and P1 each record 3/20 and 5/20 successes for the two models (8/40 pooled model/scenario observations). Both P2 columns record 0/20 for each model (0/40 pooled). The Wilson 95% upper bound for 0/20 is about 16.1%. The same twenty scenarios are reused; pooled observations are not forty independently designed attacks.

These are descriptive saved-log counts. Live model inference, execution and enforcement behind every record have not been independently authenticated. The runner also has deterministic outcome assignment. Zero observed successes does not establish zero risk. Matching P2 counts do not isolate the taint rule's incremental value. No significance, productivity or cost-saving claim should be derived from the excluded simulated fallback analysis.

For new evidence, preserve attributable model/tool/gateway traces, exact versions, raw paired outcomes, legitimate task completion, approval workload and latency. Keep generated fixtures in a different file from measured observations.
