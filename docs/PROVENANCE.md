# Source and release scope

Extracted from `annaladasur/solid-invention`, commit `797acf7bb745b96e0c26afb439df830b90be7138`, directory `agent-trust-plane/`.

[Source manifest](SOURCE-MANIFEST.txt) lists the selected inherited files. The standalone package keeps policies/tests, gateway/broker/memory/agent/merge lab source, decision-record builder, relationship model, attack manifest/examples, configuration overlays and the exact saved log used by the deck. The source Apache-2.0 license is preserved.

Publication changes add an offline policy quickstart, safe default Makefile, explicit lab opt-in, descriptive recount, CI, documentation, runnable examples and boundary tests. The legacy harness now writes generated records separately and no longer invokes the excluded analysis pipeline. The custom gateway's name is corrected to avoid suggesting it is the upstream distribution.

Excluded: unrelated talks and applications, environment files, private attack payloads, signing keys, conference binaries, generated inferential summaries, pilot productivity fixtures and the old calendar rollout guide. The deck's recount metadata is included next to the unchanged historical log. Existing model/scenario counts and their execution-provenance limitations are preserved.

Validation for this release is in [critic/validation.json](../critic/validation.json). Local policy and fresh-clone checks do not certify the experimental cluster's production readiness.
