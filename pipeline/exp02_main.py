"""E1/E2 --- Main evaluation and baseline comparison.

E1 evaluates the proposed monitor at the frozen, label-free operating point on
both real workloads, over 30 independent injection/churn draws, and reports the
per-scenario breakdown that the aggregate summarises.

E2 compares against deterministic non-ML baselines on identical sessions.  The
scored baselines are calibrated with the same protocol and the same false-alarm
budget as the proposed method; the pinning rules are parameter-free and are
reported at whatever false-alarm rate the traffic produces, which is the
operational point of the comparison.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import (ALPHA, ALPHA_GRID, SEEDS, WORKLOADS, Timer, base_config,
                             load, summarise, write_meta, write_table)
from sica.harness import run_baselines, run_experiment

METRICS = ["precision", "recall", "f1", "fpr", "specificity", "balanced_accuracy",
           "roc_auc", "pr_auc", "attack_request_detection_rate",
           "latency_requests_median", "latency_requests_mean", "n_attack_sessions"]


def main_runs() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    runs, scen, churn_fp, calib = [], [], [], []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS:
            res = run_experiment(sessions, base_config(seed))
            m = res["metrics"]
            runs.append({"workload": workload, "seed": seed, "alpha": ALPHA,
                         "threshold": res["threshold"],
                         "n_calibration_sessions": res["n_calibration_sessions"],
                         "n_evaluation_sessions": m["n_sessions"],
                         "attack_prevalence": res["injection"]["attack_prevalence"],
                         **{k: m[k] for k in METRICS}})
            for name, sm in res["per_scenario"].items():
                scen.append({"workload": workload, "seed": seed, "scenario": name,
                             **{k: sm[k] for k in
                                ["recall", "precision", "f1", "n_attack_sessions",
                                 "attack_request_detection_rate",
                                 "latency_requests_median"]}})
            for name, row in res["fp_by_churn"].items():
                churn_fp.append({"workload": workload, "seed": seed,
                                 "benign_class": name, **row})
            info = res["calibration"]
            calib.append({"workload": workload, "seed": seed,
                          "threshold": info["threshold"],
                          "calibration_alarm_rate": info["calibration_alarm_rate"],
                          "realised_fpr": m["fpr"],
                          **{f"eps_{k}": v for k, v in info["benign_firing_rate"].items()},
                          **{f"w_{k}": v for k, v in info["weights"].items()},
                          **{f"app_{k}": v for k, v in info["applicability"].items()}})
    return (pd.DataFrame(runs), pd.DataFrame(scen), pd.DataFrame(churn_fp),
            pd.DataFrame(calib))


def alpha_sweep() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for alpha in ALPHA_GRID:
            for seed in SEEDS[:15]:
                m = run_experiment(sessions, base_config(seed, alpha=alpha))["metrics"]
                rows.append({"workload": workload, "alpha": alpha, "seed": seed,
                             **{k: m[k] for k in
                                ["recall", "precision", "f1", "fpr", "roc_auc"]}})
    return pd.DataFrame(rows)


def baseline_runs() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS:
            cfg = base_config(seed)
            res = run_experiment(sessions, cfg)
            m = res["metrics"]
            rows.append({"workload": workload, "seed": seed,
                         "baseline": "SICA (proposed)", "family": "proposed",
                         "threshold": res["threshold"],
                         **{k: m[k] for k in ["TP", "TN", "FP", "FN", "precision",
                                              "recall", "f1", "fpr", "specificity",
                                              "balanced_accuracy", "roc_auc", "pr_auc"]}})
            for row in run_baselines(res["calibration_sessions"], res["sessions"],
                                     cfg.alpha):
                rows.append({"workload": workload, "seed": seed, **row})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    with Timer("E1 main evaluation (30 seeds x 2 workloads)"):
        runs, scen, churn_fp, calib = main_runs()
        write_table(runs, "e1_main_runs")
        write_table(summarise(runs, ["workload"], METRICS), "e1_main_summary")
        write_table(summarise(scen, ["workload", "scenario"],
                              ["recall", "precision", "f1",
                               "attack_request_detection_rate",
                               "latency_requests_median", "n_attack_sessions"]),
                    "e1_per_scenario")
        agg = (churn_fp.groupby(["workload", "benign_class"])
               .agg(sessions=("sessions", "sum"), false_alarms=("false_alarms", "sum"))
               .assign(fpr=lambda d: d.false_alarms / d.sessions).reset_index())
        write_table(agg, "e1_false_alarms_by_benign_class")
        write_table(calib, "e1_calibration_runs")
        write_table(summarise(calib, ["workload"],
                              [c for c in calib.columns
                               if c.startswith(("eps_", "w_", "app_"))
                               or c in ("threshold", "calibration_alarm_rate",
                                        "realised_fpr")]),
                    "e1_calibration_summary")

    with Timer("E1b false-alarm budget sweep"):
        sweep = alpha_sweep()
        write_table(sweep, "e1_alpha_sweep_runs")
        write_table(summarise(sweep, ["workload", "alpha"],
                              ["recall", "precision", "f1", "fpr", "roc_auc"]),
                    "e1_alpha_sweep")

    with Timer("E2 baseline comparison"):
        base = baseline_runs()
        write_table(base, "e2_baseline_runs")
        write_table(summarise(base, ["workload", "baseline", "family"],
                              ["precision", "recall", "f1", "fpr", "specificity",
                               "balanced_accuracy", "roc_auc", "pr_auc"]),
                    "e2_baselines")

    print("\n--- main summary ---")
    print(summarise(runs, ["workload"],
                    ["recall", "precision", "f1", "fpr", "roc_auc"]).to_string(index=False))
