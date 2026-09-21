# Run status of the artifacts in this directory

**Short answer: the results in `results/` are complete and valid, and
`pipeline/validate.py` passes 70 checks with 0 failures. There is no
`PIPELINE_DONE` marker, and that absence is expected — it is explained below.**

Written 2026-09-13. This file is documentation; it is not produced by the pipeline
and is not read by any code.

---

## What the markers mean

`run_all.sh` uses two marker files, and both have narrow meanings:

* `results/PIPELINE_ERR` — written by the `fail()` handler with the name of the
  stage that exited non-zero.
* `results/PIPELINE_DONE` — written **only** at the very end of a single
  uninterrupted `./run_all.sh` invocation in which *every* stage succeeded.

Both are deleted at the start of each run.

## What actually happened

| | |
|---|---|
| Run started | 2026-09-12, via `./run_all.sh` |
| Stages that ran inside that invocation | preflight · tests (50 passed) · E0 · E1+E2 · E3 · E5 · E6 · E4 (a, b, c) · E7 |
| Where it stopped | `make_tables` raised `AttributeError` — it read a column name (`state_bytes_measured`) that `e6_efficiency.csv` does not have, and its `level_word` map omitted `L5` |
| Marker written at that point | `PIPELINE_ERR` containing `make_tables` (14:33:53) |

All **experiment** stages completed successfully before that point. The failure was
confined to the reporting layer, which generates LaTeX tables from result CSVs and
computes nothing scientific.

The two reporting-layer defects were then corrected in `pipeline/make_tables.py`
(no detector, dataset, seed, metric or methodology change), and the three remaining
stages were executed **individually** rather than by re-running the whole pipeline,
so that the completed experiments were not recomputed:

| Stage | Log | Outcome |
|---|---|---|
| `make_tables.py` | `results/logs/make_tables.log` (14:43:39) | 12/12 `.tex` written, including `numbers.tex` |
| `exp08_figures.py` | `results/logs/figures.log` (14:43:48) | 6 figures, PDF + PNG |
| `pipeline/validate.py` | `results/logs/validate.log` | **70 passed, 0 failed — validation passed** |

## Why `PIPELINE_DONE` is absent, and why it was not created by hand

`PIPELINE_DONE` asserts one specific thing: that a single `run_all.sh` invocation
carried every stage to completion. That is not what happened here — the last three
stages were run separately. Creating the marker manually would make the repository
assert something untrue about its own provenance, so it was not created.

The stale `PIPELINE_ERR` was removed on 2026-09-13, because it asserted that
`make_tables` had failed when the corrected stage had since succeeded; the file was
actively false. Nothing was lost: the original failure is still recorded in
`results/RUN_ALL.log`, which ends with `FAILED at stage: make_tables`, and the
successful rerun is recorded in `results/logs/make_tables.log`.

**Note that `results/RUN_ALL.log` therefore ends in a failure line while the
artifacts beside it are complete.** That log is the honest record of the single
`run_all.sh` invocation; it is not a record of the three stages run afterwards.

## How to obtain a clean `PIPELINE_DONE`

Re-run `./run_all.sh` end to end. Every stage now succeeds, so the marker would be
written. This would recompute E0–E7 (~72 minutes) and overwrite the current result
CSVs with numerically equivalent ones. It was **not** done, because the existing
results are valid and the project's rule is not to regenerate frozen scientific
artifacts without cause.

Before any such re-run, note the hazard recorded in
`docs/EXPERIMENT_CONTRACT.md` §24: `run_all.sh` clears only the marker files, and
`validate.py` checks artifact *existence*, not freshness. A re-run over a populated
`results/` that failed partway could leave a mixture of generations. Archive the
current `results/` first, as was done for the superseded run now in
`results_archive/2026-09-05_prefix_abandoned/`.

## Current state, in one table

| Item | State |
|---|---|
| Experiment result tables | 39 CSV (27 contracted + 12 per-run), all valid |
| Metadata | 3 JSON, including `leakage_report.json` (26 checks passed, 0 failed) |
| Figures | 6, as PDF and PNG |
| Generated paper tables | 12 `.tex` in `paper/tables/` |
| `pipeline/validate.py` | **70 passed, 0 failed** |
| Test suite | 50 passed, 0 failed |
| `PIPELINE_ERR` | removed (was false) |
| `PIPELINE_DONE` | absent by design — see above |
