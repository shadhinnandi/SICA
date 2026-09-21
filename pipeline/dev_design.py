"""Development study: fixes the three open design choices on a disjoint seed block.

Design decisions must not be taken on the seeds used for the reported results.
This script therefore runs on development seeds 100-129, which draw different
injection and churn realisations from the same underlying traffic.  The choices
it settles --- the evidence rule, reference migration, and the default
false-alarm budget --- are then frozen and applied unchanged to the reporting
seeds 0-29.
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import WORKLOADS, base_config, load, summarise, write_table, Timer
from sica.harness import run_experiment
from sica.monitor import MonitorConfig

DEV_SEEDS = tuple(range(100, 120))

if __name__ == "__main__":
    rows = []
    with Timer("development design study (seeds 100-119)"):
        for workload in WORKLOADS:
            sessions = load(workload)
            for seed in DEV_SEEDS:
                for mig in (True, False):
                    for ev in ("max", "accumulator"):
                        for alpha in (0.005, 0.01, 0.02):
                            m = run_experiment(sessions, base_config(
                                seed, alpha=alpha,
                                monitor=MonitorConfig(migrate_reference=mig,
                                                      evidence=ev)))["metrics"]
                            rows.append({"workload": workload, "seed": seed,
                                         "migrate": mig, "evidence": ev, "alpha": alpha,
                                         **{k: m[k] for k in
                                            ["recall", "precision", "f1", "fpr", "roc_auc"]}})
        d = pd.DataFrame(rows)
        write_table(d, "dev_design_runs")
        s = summarise(d, ["workload", "migrate", "evidence", "alpha"],
                      ["recall", "precision", "f1", "fpr", "roc_auc"])
        write_table(s, "dev_design")
        print(s[["workload", "migrate", "evidence", "alpha", "recall_mean",
                 "fpr_mean", "f1_mean", "roc_auc_mean"]].round(4).to_string(index=False))
