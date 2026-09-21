"""Development study: which invariants earn their place.

Run on the disjoint development seed block so that the composition of the final
invariant set is not chosen against the seeds used for the reported results.
"""
import sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import WORKLOADS, base_config, load, summarise, write_table, Timer
from sica.harness import run_experiment
from sica.invariants import INVARIANTS

DEV_SEEDS = tuple(range(100, 120))
V1, V2, V3, V4, V5, V6 = INVARIANTS
CANDIDATES = {
    "full_V1-V6":        INVARIANTS,
    "V1_V2_V3_V6":       (V1, V2, V3, V6),     # incumbent after round 1
    "V1_V2_V6":          (V1, V2, V6),         # drop the explicit fork marker
    "V1_V2_V3":          (V1, V2, V3),
    "V1_V2":             (V1, V2),
    "V1_V3_V6":          (V1, V3, V6),
    "V2_V3_V6":          (V2, V3, V6),
    "V1_V2_V3_V4_V6":    (V1, V2, V3, V4, V6),
    "V1_V2_V3_V5_V6":    (V1, V2, V3, V5, V6),
}
METRICS = ["precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]

if __name__ == "__main__":
    rows = []
    with Timer("development invariant-set study (seeds 100-119)"):
        for workload in WORKLOADS:
            sessions = load(workload)
            for name, enabled in CANDIDATES.items():
                for seed in DEV_SEEDS:
                    m = run_experiment(sessions, base_config(seed, enabled=enabled))["metrics"]
                    rows.append({"workload": workload, "variant": name, "seed": seed,
                                 **{k: m[k] for k in METRICS}})
        d = pd.DataFrame(rows)
        write_table(d, "dev_invariants_runs")
        s = summarise(d, ["workload", "variant"], METRICS)
        write_table(s, "dev_invariants")
        print(s[["workload", "variant", "recall_mean", "precision_mean", "f1_mean",
                 "fpr_mean", "roc_auc_mean", "pr_auc_mean"]].round(4).to_string(index=False))
