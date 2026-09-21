"""E4 --- Robustness to the assumptions that the benchmark itself makes.

Every quantity swept here is an assumption about the deployment or the adversary
that cannot be measured from the available logs.  Reporting a single value for
any of them would make the headline result a function of an unverifiable choice,
so each is varied across its plausible range and the result is reported as a
curve.

* *Masquerade level and concurrency* --- the adversary's capability.  Each cell
  is evaluated in isolation so that the aggregate is not hiding a bimodal
  outcome.
* *Benign flapping rate* --- the prevalence of dual-homed clients, which is the
  detector's only structural false-alarm source.
* *Benign monotone churn rate* --- how often legitimate clients move.
* *Attack fraction* --- how much traffic the adversary issues once inside.
* *Theft position* --- how early in the session the identifier is stolen, and
  therefore how much context the monitor has established beforehand.
* *Theft delay* --- how long the adversary waits before using the identifier.
* *Minimum session length* --- how much context is available before the theft.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline.common import SEEDS, WORKLOADS, Timer, base_config, load, summarise, write_table
from sica.churn import ChurnConfig
from sica.harness import run_experiment
from sica.inject import LEVELS_ALL, MODES
from sica.harness import run_baselines

METRICS = ["precision", "recall", "f1", "fpr", "roc_auc",
           "attack_request_detection_rate", "latency_requests_median"]
SEEDS_R = SEEDS[:20]


def _row(workload, seed, factor, value, res, **extra):
    m = res["metrics"]
    return {"workload": workload, "seed": seed, "factor": factor, "value": value,
            "n_attack_sessions": m["n_attack_sessions"],
            **{k: m[k] for k in METRICS}, **extra}


def scenario_grid() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Each adversary cell in isolation, for the monitor and for every baseline.

    Isolating the cells matters because the aggregate over a scenario mixture is
    a function of the mixture weights, which are an arbitrary prior over
    adversary capability.  Running the baselines in the same cells shows which
    adversaries defeat which defence, rather than only which defence has the
    larger average.
    """
    rows, brows = [], []
    for workload in WORKLOADS:
        sessions = load(workload)
        for level in LEVELS_ALL:
            for mode in MODES:
                for seed in SEEDS_R:
                    cfg = base_config(seed, levels=(level,), modes=(mode,))
                    res = run_experiment(sessions, cfg)
                    rows.append(_row(workload, seed, "scenario", f"{level}_{mode}",
                                     res, level=level, mode=mode))
                    m = res["metrics"]
                    brows.append({"workload": workload, "seed": seed, "level": level,
                                  "mode": mode, "detector": "SICA (proposed)",
                                  **{k: m[k] for k in
                                     ["recall", "precision", "f1", "fpr", "roc_auc"]}})
                    for row in run_baselines(res["calibration_sessions"],
                                             res["sessions"], cfg.alpha):
                        brows.append({"workload": workload, "seed": seed,
                                      "level": level, "mode": mode,
                                      "detector": row["baseline"],
                                      **{k: row[k] for k in
                                         ["recall", "precision", "f1", "fpr", "roc_auc"]}})
    return pd.DataFrame(rows), pd.DataFrame(brows)


def sweeps() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_R:
            for rate in (0.0, 0.01, 0.02, 0.05, 0.10, 0.20):
                res = run_experiment(sessions, base_config(
                    seed, churn=ChurnConfig(monotone_rate=0.15, flapping_rate=rate)))
                rows.append(_row(workload, seed, "flapping_rate", rate, res))
            for rate in (0.0, 0.05, 0.15, 0.30, 0.50):
                res = run_experiment(sessions, base_config(
                    seed, churn=ChurnConfig(monotone_rate=rate, flapping_rate=0.05)))
                rows.append(_row(workload, seed, "monotone_rate", rate, res))
            for frac in (0.05, 0.10, 0.20, 0.40, 0.60):
                res = run_experiment(sessions, base_config(seed, attack_fraction=frac))
                rows.append(_row(workload, seed, "attack_fraction", frac, res))
            for rate in (0.02, 0.05, 0.10, 0.20, 0.35):
                res = run_experiment(sessions, base_config(seed, attack_rate=rate))
                rows.append(_row(workload, seed, "attack_rate", rate, res))
            for lo, hi in ((0.10, 0.20), (0.25, 0.50), (0.50, 0.70), (0.70, 0.85)):
                res = run_experiment(sessions, base_config(
                    seed, earliest_takeover=lo, latest_takeover=hi))
                rows.append(_row(workload, seed, "theft_position", f"{lo:.2f}-{hi:.2f}", res))
            for delay in (0.0, 1.0, 60.0, 600.0):
                res = run_experiment(sessions, base_config(seed, theft_delay_s=delay))
                rows.append(_row(workload, seed, "theft_delay_s", delay, res))
        for min_req in (7, 10, 15, 20):
            subset = load(workload, min_requests=min_req)
            if len(subset) < 60:
                continue
            for seed in SEEDS_R:
                res = run_experiment(subset, base_config(seed))
                rows.append(_row(workload, seed, "min_requests", min_req, res))
    return pd.DataFrame(rows)


def churn_crossover() -> pd.DataFrame:
    """Where address pinning stops being viable, as benign address churn grows.

    Address pinning has no knob: it fires on every address change and therefore
    inherits the benign address-churn rate as its false-alarm rate.  The
    proposed monitor is calibrated to a fixed budget instead.  This sweep
    locates the churn rate at which the two exchange places, which is the
    quantity an operator actually needs in order to choose between them.
    """
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for rate in (0.0, 0.01, 0.02, 0.05, 0.10, 0.20, 0.35):
            for seed in SEEDS_R:
                cfg = base_config(seed, churn=ChurnConfig(monotone_rate=rate,
                                                          flapping_rate=0.05))
                res = run_experiment(sessions, cfg)
                m = res["metrics"]
                rows.append({"workload": workload, "seed": seed,
                             "monotone_rate": rate, "detector": "SICA (proposed)",
                             **{k: m[k] for k in
                                ["precision", "recall", "f1", "fpr", "roc_auc"]}})
                for row in run_baselines(res["calibration_sessions"], res["sessions"],
                                         cfg.alpha):
                    rows.append({"workload": workload, "seed": seed,
                                 "monotone_rate": rate, "detector": row["baseline"],
                                 **{k: row[k] for k in
                                    ["precision", "recall", "f1", "fpr", "roc_auc"]}})
    return pd.DataFrame(rows)


if __name__ == "__main__":
    with Timer("E4a adversary grid"):
        grid, grid_base = scenario_grid()
        write_table(grid, "e4_scenario_grid_runs")
        write_table(summarise(grid, ["workload", "level", "mode"], METRICS),
                    "e4_scenario_grid")
        write_table(grid_base, "e4_scenario_baselines_runs")
        write_table(summarise(grid_base, ["workload", "detector", "level", "mode"],
                              ["recall", "precision", "f1", "fpr"]),
                    "e4_scenario_baselines")

    with Timer("E4b assumption sweeps"):
        sw = sweeps()
        write_table(sw, "e4_sweep_runs")
        write_table(summarise(sw, ["workload", "factor", "value"], METRICS),
                    "e4_sweeps")

    with Timer("E4c address-churn crossover against baselines"):
        cross = churn_crossover()
        write_table(cross, "e4_crossover_runs")
        write_table(summarise(cross, ["workload", "detector", "monotone_rate"],
                              ["precision", "recall", "f1", "fpr", "roc_auc"]),
                    "e4_crossover")

    print(summarise(grid, ["workload", "level", "mode"],
                    ["recall", "fpr"]).to_string(index=False))
