# Archived results — abandoned pre-fix run of 2026-09-05

**Archived on** 2026-09-12, during the Part-4B preflight gate.
**Status: VOID. Not reportable. Retained as evidence only.**
**Nothing in this directory was deleted or modified.** File-level integrity is recorded in
`MANIFEST.sha256.txt` (46 files: path, byte size, original mtime, SHA-256), captured
immediately **before** the move.

---

## What this is

The complete output of a `./run_all.sh` execution started on 2026-09-05. It is the run that
**never finished**: `results/RUN_ALL.log` ends at `== E4c address-churn crossover against
baselines` with no completion line, and neither `PIPELINE_DONE` nor `PIPELINE_ERR` was ever
written. The process died or was interrupted rather than failing cleanly.

| | |
|---|---|
| Stages that completed | E0 corpus · E1 main + budget sweep · E2 baselines · E3 ablation · E4a adversary grid · E4b assumption sweeps · E5 leakage · E6 efficiency |
| Stages that never ran | E4c crossover · E7 statistics · `make_tables` · `exp08_figures` · `validate` |
| Result tables present | 34 CSVs (30 experiment + 4 development-study) |
| Missing tables | `e4_crossover.csv`, `e7_baseline_tests.csv`, `e7_base_rate.csv` |
| Figures | none — `exp08_figures` never ran |
| Paper tables | none — `make_tables` never ran |

## Why it is void

Every file here was produced **before** the correctness work of Parts 2, 2.5 and 3.5. All
result files are dated 2026-09-05; every fix is dated 2026-09-12. The defects listed below
were live in the code that produced these numbers, so the numbers cannot be quoted, compared
against, or used to sanity-check a new run.

| ID | Defect active in this run | Effect on these numbers |
|---|---|---|
| **C1** | `threshold_for_budget` took a `(1−α)` quantile over a heavily tied score, then alerted on `≥` | The declared 1% false-alarm budget was **missed on its own calibration sample** — measured 2.15% (W1) and 1.85% (W2), and 3.94% on one seed. Every threshold-dependent metric here sits at an operating point that was never the declared one |
| **C2** | Reported envelope was L0–L3 only | Every evaluated attack carried an address change, so `pin_ip` scored recall **exactly 1.0000** by construction. The baseline comparison in these files is uninformative on its recall axis |
| **H1** | Masquerade levels derived from `Session.client` (pre-churn address) | L2/L3 cells are mislabelled where the victim churned before the theft, biased toward easier detection |
| **H2** | `_bump_version` could not bump AptHTTP versions | On W2, `M2_agent_update` and the agent half of `M3_combined` were no-ops: measured ε(V1) = **0.00000**. The benign class is mischaracterised and V1's false-alarm cost on W2 is understated |
| **H3** | `pr_auc` had no tie correction | Every `pr_auc` value here is order-dependent; an all-tied sample scored 0.833 where the correct average precision is 0.500 |
| **H5** | Ranking AUC reported for binary pinning rules | `roc_auc` columns for `pin_*` rows are balanced accuracy wearing a ranking label |
| **M1** | Session identifiers embedded the salted `hash()` | Identifiers here are not reproducible across processes |
| **M2** | Takeover theft point re-derived from the 40-request cap | The `theft_position` sweep was inert for long sessions; a requested window of [0.20, 0.30] produced thefts at 0.600 |
| **D1** | Concurrent injection delay unbounded by the victim's window | At `theft_delay_s` ≥ 60 s only **34.2%** of "concurrent" sessions actually interleaved; the rest were takeovers carrying a concurrent label |

## What these files were legitimately used for, and still are

They are **evidence**, and several conclusions in the audit trail rest on them. They are cited
by:

* `docs/ARCHITECTURE_AUDIT.md` — the C1/C2/H1–H5 findings were measured from these tables
  (e.g. the 2.15%/1.85% calibration alarm rates from `e1_calibration_summary.csv`, `pin_ip`
  recall 1.0000 from `e2_baselines.csv`, ε(V1)=0.00000 on W2, the `distinct_paths` 0.732
  shortcut from `e5_marginal_audit.csv`).
* `docs/DATASET_VERIFICATION.md` — corpus counts cross-checked against `e0_corpus.csv`.
* `docs/ARCHITECTURE_FREEZE.md` — the before/after tables quote these as the "before" column.

Deleting them would destroy the basis of those findings. That is why this archive exists
rather than a cleanup.

### The development-study tables are a special case

`dev_design*.csv` and `dev_invariants*.csv` (seeds 100–119) are the artifacts on which the
**locked invariant set was selected**. They are also pre-fix, and the selection was made under
the C1 threshold defect — but the selection criterion was **threshold-free ROC AUC**, which is
unaffected by that defect. This is the documented reason the lock survives the corrections
(`docs/ARCHITECTURE_FREEZE.md` §2). Whether the corrected threshold changes `v3`'s
cost/benefit at the *operating point* remains open as audit item **U4**, to be settled on
development seeds only.

## Why it was archived rather than left in place

`run_all.sh` clears only `PIPELINE_DONE` and `PIPELINE_ERR`; it does not clear result tables.
`pipeline/validate.py` checks artifact **existence, not freshness**. A reporting run that
failed partway would therefore have left a silent mixture of valid 2026-09-12 results and void
2026-09-05 results — and would still have passed validation. That failure mode is not
hypothetical: this very run died partway, which is why three tables are missing while 34 stale
ones remained.

Archiving guarantees the reporting run starts from an empty output tree.

## Rules for this directory

1. **Do not delete.** It is the evidence base for the audit findings above.
2. **Do not quote any number from it** in the manuscript, in tables, or in comparisons.
3. **Do not let any pipeline stage read from it.** No script references
   `results_archive/`; outputs are written to and read from `results/` only.
4. If a future run is also abandoned, archive it under its own dated directory rather than
   overwriting this one.

## Verification

```bash
cd results_archive/2026-09-05_prefix_abandoned
awk 'NR>1 {print $4 "  " $1}' MANIFEST.sha256.txt | (cd . && sha256sum -c -)
```

Paths in the manifest are relative to the original `results/` directory, which maps onto this
archive directory one-to-one.
