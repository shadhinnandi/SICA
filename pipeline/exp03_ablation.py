"""E3 --- Ablation over the invariant set and over the three design choices.

Four families are ablated, each against the identical evaluation draw:

1. *Leave-one-invariant-out.*  Each invariant is removed and the remaining ones
   are re-weighted and re-thresholded by the same calibration procedure, so the
   comparison is between two fully and independently calibrated detectors rather
   than between one detector and a de-tuned version of itself.
2. *Single-invariant.*  Each invariant alone, to separate a component that
   carries evidence from one that merely survives removal.
3. *Weighting.*  Benign-rarity surprisal weighting against the uniform control.
4. *Design choices.*  Reference migration on/off and evidence rule max/accumulator.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import SEEDS, WORKLOADS, Timer, base_config, load, summarise, write_table
from sica.harness import run_experiment
from sica.invariants import DEFAULT_INVARIANTS, INVARIANTS
from sica.monitor import MonitorConfig

METRICS = ["precision", "recall", "f1", "fpr", "balanced_accuracy", "roc_auc", "pr_auc"]
SEEDS_ABL = SEEDS[:20]


def _row(workload, seed, family, variant, res):
    m = res["metrics"]
    out = {"workload": workload, "seed": seed, "family": family, "variant": variant,
           "threshold": res["threshold"], **{k: m[k] for k in METRICS}}
    for name in INVARIANTS:
        out[f"w_{name}"] = res["weights"].get(name, 0.0)
    return out


def ablations() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_ABL:
            rows.append(_row(workload, seed, "reference", "full",
                             run_experiment(sessions, base_config(seed))))

            for drop in DEFAULT_INVARIANTS:
                keep = tuple(n for n in DEFAULT_INVARIANTS if n != drop)
                rows.append(_row(workload, seed, "leave_one_out", f"minus_{drop}",
                                 run_experiment(sessions, base_config(seed, enabled=keep))))

            # The invariants that were implemented, evaluated on the development
            # seeds and then rejected: adding each one back to the retained set
            # is reported so that the rejection is auditable rather than asserted.
            rejected = [n for n in INVARIANTS if n not in DEFAULT_INVARIANTS]
            for add in rejected:
                keep = tuple(n for n in INVARIANTS
                             if n in DEFAULT_INVARIANTS or n == add)
                rows.append(_row(workload, seed, "restored", f"plus_{add}",
                                 run_experiment(sessions, base_config(seed, enabled=keep))))
            rows.append(_row(workload, seed, "restored", "plus_all_rejected",
                             run_experiment(sessions, base_config(seed, enabled=INVARIANTS))))

            for only in INVARIANTS:
                try:
                    res = run_experiment(sessions, base_config(seed, enabled=(only,)))
                except ValueError:
                    continue          # invariant not applicable to this workload
                rows.append(_row(workload, seed, "single", f"only_{only}", res))

            rows.append(_row(workload, seed, "weighting", "equal_weights",
                             run_experiment(sessions, base_config(seed, weighting="equal"))))
            rows.append(_row(workload, seed, "design", "no_migration",
                             run_experiment(sessions, base_config(
                                 seed, monitor=MonitorConfig(migrate_reference=False,
                                                             evidence="max")))))
            rows.append(_row(workload, seed, "design", "accumulator",
                             run_experiment(sessions, base_config(
                                 seed, monitor=MonitorConfig(migrate_reference=True,
                                                             evidence="accumulator")))))
    return pd.DataFrame(rows)


if __name__ == "__main__":
    with Timer("E3 ablation"):
        runs = ablations()
        write_table(runs, "e3_ablation_runs")
        summary = summarise(runs, ["workload", "family", "variant"], METRICS)
        write_table(summary, "e3_ablation")
        print(summary[["workload", "family", "variant", "recall_mean", "fpr_mean",
                       "f1_mean", "roc_auc_mean"]].to_string(index=False))
