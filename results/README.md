# Historical evidence

`runs.jsonl` is an immutable snapshot from the talk's source repository, not a newly verified benchmark. See [evidence boundaries](../docs/EVIDENCE.md). Do not append new runs to this file.

`Saved-Log-Recount.json` is the deck's machine-readable recount. Its `source` path is relative to the original monorepository; the same file is `results/runs.jsonl` here. `make recount` independently re-derives the counts and Wilson intervals from it.
