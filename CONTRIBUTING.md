# Contributing

Use a topic branch and describe the intended boundary and its trusted inputs. Run `make test` and `make demo` before submitting. Add negative cases for missing identity, stale/mismatched approval, cross-repository access and malformed records when those paths change.

Keep generated data distinct from observed records. Do not overwrite results/runs.jsonl, fabricate a successful live test, or publish real credentials. Include the command, dependency versions, environment and evidence provenance with a measurement. Changes to a YAML-embedded Python service must also update its standalone source (and vice versa).

The project currently supports the offline policy quickstart. Cluster integrations need separate end-to-end validation; passing unit tests does not promote them to production readiness.
