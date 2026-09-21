# Documentation index

This project has two tiers of documentation: **working documents** at the
repository root, which describe how to use the project, and **frozen records** in
`docs/`, which fix what was decided and why. Where they disagree, the frozen
record in `docs/` is authoritative for methodology.

Last updated 2026-09-13.

---

## Start here

| If you want to… | Read |
|---|---|
| Understand what the project is, in ten minutes | [`../README.md`](../README.md) |
| Run it yourself | [`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) |
| Know what was actually done and what may be claimed | [`EXPERIMENT_CONTRACT.md`](EXPERIMENT_CONTRACT.md) |
| See the project's current state at a glance | [`../RESEARCH_RECORD.md`](../RESEARCH_RECORD.md) |

A reasonable reading order for a new researcher:
**README → RESEARCH_RECORD → EXPERIMENT_CONTRACT → DATASET_FREEZE → ARCHITECTURE_FREEZE**.
Everything else is detail or evidence.

## By subject

| Subject | Document | Tier |
|---|---|---|
| **Architecture** — detector, invariants, calibration, threshold rule | [`ARCHITECTURE_FREEZE.md`](ARCHITECTURE_FREEZE.md) | frozen |
| **Datasets** — sources, hashes, licence, privacy, limitations | [`DATASET_FREEZE.md`](DATASET_FREEZE.md) | frozen |
| **Dataset verification** — how the above was independently checked | [`DATASET_VERIFICATION.md`](DATASET_VERIFICATION.md) | evidence |
| **Experiments** — what each stage does and how to run it | [`../EXPERIMENTS.md`](../EXPERIMENTS.md) | working |
| **Experiment contract** — pre-registered design, metrics, claims | [`EXPERIMENT_CONTRACT.md`](EXPERIMENT_CONTRACT.md) | frozen |
| **Reproducibility** — install, run, determinism, limitations | [`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md) | working |
| **Reproducibility guarantees** — identifiers, conditions, metrics | [`REPRODUCIBILITY_FREEZE.md`](REPRODUCIBILITY_FREEZE.md) | frozen |
| **Data description** — corpora, churn, injection, labels, splits | [`../DATASET.md`](../DATASET.md) | working |
| **Change control** — what is locked and how to unlock it | [`../CHECKPOINT.md`](../CHECKPOINT.md) | frozen |
| **Defect history** — what was wrong and how it was fixed | [`../AUDIT.md`](../AUDIT.md) | evidence |
| **Architecture audit** — the full read-only audit that drove the fixes | [`ARCHITECTURE_AUDIT.md`](ARCHITECTURE_AUDIT.md) | evidence |
| **Test plan** — which finding each regression test guards | [`TEST_PLAN.md`](TEST_PLAN.md) | evidence |
| **L5 reporting fix** — the reporting-layer level-coverage defect and its correction | [`L5_REPORTING_FIX.md`](L5_REPORTING_FIX.md) | evidence |
| **Paper claim audit** — every manuscript claim traced to frozen evidence | [`PAPER_CLAIM_AUDIT.md`](PAPER_CLAIM_AUDIT.md) | evidence |
| **Run status** — why there is no `PIPELINE_DONE` marker | [`../results/RUN_STATUS.md`](../results/RUN_STATUS.md) | evidence |
| **Input attribution** — sources, URLs, hashes, licences, privacy | [`../CITATION_OF_INPUTS.txt`](../CITATION_OF_INPUTS.txt) | legal |

## What supersedes what

The project was audited and corrected in stages. Later documents supersede
earlier ones on specific points; **none of the earlier documents were deleted**,
because the audit findings are evidence for the corrections.

| Later document | Supersedes | On what |
|---|---|---|
| `ARCHITECTURE_FREEZE.md` | `ARCHITECTURE_AUDIT.md` | The audit *found* the defects; the freeze records the corrected, locked state. Read the audit for *why*, the freeze for *what is true now* |
| `REPRODUCIBILITY_FREEZE.md` | parts of `../REPRODUCIBILITY.md` | Identifier determinism, experiment-condition handling, metric definitions, binary-baseline reporting |
| `DATASET_FREEZE.md` | parts of `../DATASET.md` | Licensing, terminology, the timestamp limitation, the final benchmark composition |
| `DATASET_VERIFICATION.md` | any earlier provenance claim | The corpora were verified byte-identical to upstream; several earlier descriptions were wrong |
| `EXPERIMENT_CONTRACT.md` | `../EXPERIMENTS.md` | Methodology, seed policy, pre-registered claims. `EXPERIMENTS.md` is the operational how-to; the contract is the commitment |
| `../results/RUN_STATUS.md` | the marker files | `results/RUN_ALL.log` ends in a failure line that a later corrected rerun resolved |

## A note on the configuration

`../config.yaml` is a **descriptive mirror only — no code loads it**. The
executable source of truth is `../pipeline/common.py` together with the component
defaults in `../sica/`. If the two disagree, the code is correct and the mirror is
stale.

## Historical evidence — do not delete

| Location | What it is |
|---|---|
| `../results_archive/2026-09-05_prefix_abandoned/` | The superseded pre-fix run: 48 files with a pre-move SHA-256 manifest and a provenance note. **Every number in it is void**, but the audit findings were measured from it, so it is the evidence base for the corrections |
| `../AUDIT.md`, `ARCHITECTURE_AUDIT.md`, `DATASET_VERIFICATION.md` | Records of what was wrong. Kept deliberately: a repository that only shows its final state cannot be checked |
