# Authorization configuration reference

P0/P1/P2-off/P2-on overlays define the four conditions explained in [docs/EVIDENCE.md](../../docs/EVIDENCE.md). The files are configurations, not proof that each control was enforced in an attributable live run.

`run_matrix.py` is retained as a legacy experimental harness. It uses posture-specific outcome assignment and a simulated dry-run branch. It must not be used to claim measured security improvement. It writes generated runs separately from the historical log in this release and requires explicit experimental opt-in. The old `--update-analysis` pipeline is not included; use the descriptive `scripts/recount.py` for historical records.
