"""E7 --- Statistical analysis and operating-point interpretation.

*Determinism.*  The detector is a deterministic function of a request stream:
given the same traffic it always produces the same decisions.  The variability
reported here therefore comes entirely from the benchmark construction --- which
sessions are targeted, which donors supply the attacker's traffic, and which
benign sessions receive mobility --- and from the calibration split.  Repetition
is over 30 independent draws of that construction, not over model
initialisations.

*Comparisons.*  Each draw is evaluated by every detector on identical sessions,
so comparisons are paired.  The Wilcoxon signed-rank test is used because the
per-draw differences are not assumed normal, and the family of comparisons
against the proposed method is corrected with Holm's step-down procedure.
Effect size is reported as the median paired difference, since a p-value on 30
paired draws says only that a difference is stable, not that it matters.

*Base rates.*  Precision measured at the benchmark's 20% attack prevalence does
not transfer to deployment, where hijacked sessions are rare.  Precision and
daily alert volume are therefore recomputed from the measured true- and
false-positive rates across realistic prevalences.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import TABLES, Timer, write_table

PREVALENCES = (1e-5, 1e-4, 1e-3, 1e-2, 5e-2, 2e-1)


def holm(pvalues: list[float]) -> list[float]:
    order = np.argsort(pvalues)
    m = len(pvalues)
    adjusted = np.empty(m)
    running = 0.0
    for rank, idx in enumerate(order):
        running = max(running, (m - rank) * pvalues[idx])
        adjusted[idx] = min(1.0, running)
    return adjusted.tolist()


def paired_tests(frame: pd.DataFrame, group_col: str, reference: str,
                 keys: list[str], metrics: list[str]) -> pd.DataFrame:
    rows = []
    for key, g in frame.groupby(keys, sort=True):
        key = key if isinstance(key, tuple) else (key,)
        ref = g[g[group_col] == reference].set_index("seed")
        if ref.empty:
            continue
        pending = []
        for name, sub in g[g[group_col] != reference].groupby(group_col, sort=True):
            sub = sub.set_index("seed")
            common = ref.index.intersection(sub.index)
            if len(common) < 6:
                continue
            row = dict(zip(keys, key))
            row.update({"comparison": f"{reference} vs {name}", "n_pairs": len(common)})
            for m in metrics:
                a = ref.loc[common, m].to_numpy(dtype=float)
                b = sub.loc[common, m].to_numpy(dtype=float)
                diff = a - b
                row[f"{m}_median_diff"] = float(np.median(diff))
                if np.allclose(diff, 0.0):
                    row[f"{m}_p"] = 1.0
                else:
                    row[f"{m}_p"] = float(stats.wilcoxon(
                        a, b, zero_method="wilcox", alternative="two-sided").pvalue)
            pending.append(row)
        for m in metrics:
            adj = holm([r[f"{m}_p"] for r in pending])
            for r, p in zip(pending, adj):
                r[f"{m}_p_holm"] = p
        rows.extend(pending)
    return pd.DataFrame(rows)


def base_rate(summary: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, r in summary.iterrows():
        tpr, fpr = float(r["recall_mean"]), float(r["fpr_mean"])
        for pi in PREVALENCES:
            tp = pi * tpr
            fp = (1 - pi) * fpr
            rows.append({"workload": r["workload"], "prevalence": pi,
                         "tpr": tpr, "fpr": fpr,
                         "precision": tp / (tp + fp) if tp + fp else float("nan"),
                         "alerts_per_million_sessions": (tp + fp) * 1e6,
                         "true_alerts_per_million": tp * 1e6,
                         "false_alerts_per_million": fp * 1e6,
                         "missed_hijacks_per_million": pi * (1 - tpr) * 1e6})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    with Timer("E7 statistical analysis"):
        base = pd.read_csv(TABLES / "e2_baseline_runs.csv")
        tests = paired_tests(base, "baseline", "SICA (proposed)", ["workload"],
                             ["f1", "recall", "fpr", "roc_auc", "balanced_accuracy"])
        write_table(tests, "e7_baseline_tests")

        abl = pd.read_csv(TABLES / "e3_ablation_runs.csv")
        abl = abl.assign(variant=abl.variant.where(abl.family != "reference", "full"))
        for family in ("leave_one_out", "restored", "single", "weighting", "design"):
            sub = abl[abl.family.isin(["reference", family])]
            t = paired_tests(sub, "variant", "full", ["workload"],
                             ["f1", "recall", "fpr", "roc_auc"])
            if not t.empty:
                t.insert(1, "ablation_family", family)
                write_table(t, f"e7_ablation_tests_{family}")

        summary = pd.read_csv(TABLES / "e1_main_summary.csv")
        write_table(base_rate(summary), "e7_base_rate")
        print(tests.to_string(index=False))
