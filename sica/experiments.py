"""The study: data loading, frozen configuration and experiments E0-E7.

Each ``run_*`` function reproduces one group of result tables in
``results/tables/``.  ``run.py`` calls them; nothing here needs to be run by hand.

    E0  run_e0          corpus statistics and sessionisation
    E1  run_e1, run_e1b main result at alpha = 1%; false-alarm budget sweep
    E2  run_e2          SICA against the non-ML baselines on identical sessions
    E3  run_e3          ablation: remove / restore invariants, design switches
    E4  run_e4          adversary grid L0-L5 x {takeover, concurrent}, sweeps
    E5  run_e5          leakage audit of the benchmark construction
    E6  run_e6          throughput, latency and memory of the detector
    E7  run_e7          paired statistical tests and base-rate table

Reporting seeds are 0-29.  Development seeds 100-119 (``run_dev_*``) were used
only to choose the design and are disjoint from the reporting seeds.
"""
from __future__ import annotations

import gc
import json
import platform
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

from .benchmark import LEVELS_ALL, MODES, ChurnConfig
from .detector import ContinuityMonitor, MonitorConfig, SessionState, decision, threshold_for_budget
from .evaluation import (ExperimentConfig, bootstrap_ci, confusion, pr_auc, rate_metrics,
                         roc_auc, run_baselines, run_experiment)
from .fingerprint import binding_of, ip_prefix24, ip_scope16, parse_user_agent
from .invariants import DEFAULT_INVARIANTS, INVARIANTS
from .sessionize import parse_log, sessionize


# ============================================================================
# Frozen study configuration, data loading and I/O
# ============================================================================

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
TABLES = ROOT / "results" / "tables"
FIGURES = ROOT / "results" / "figures"
SUMMARY = ROOT / "results" / "summary"
for _d in (TABLES, FIGURES, SUMMARY):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Frozen study configuration.  Every experiment reads these values; nothing is
# selected against evaluation labels.
# ---------------------------------------------------------------------------
SEEDS = tuple(range(30))
ALPHA = 0.01                      # primary session-level false-alarm budget
ALPHA_GRID = (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.10)
IDLE_SECONDS = 1800.0
MIN_REQUESTS = 7
ATTACK_RATE = 0.20
ATTACK_FRACTION = 0.40
MONOTONE_CHURN = 0.15
FLAPPING_CHURN = 0.05

# ``label`` is descriptive only: it fills the ``description`` column of e0_corpus.csv.
WORKLOADS = {
    "W1_web": {"file": "W1/apache_sample_1.log", "dialect": "combined",
               "label": "Apache combined access log, human web browsing "
                        "(Elastic Examples sample corpus)"},
    "W2_apt": {"file": "W2/nginx_real.log", "dialect": "combined",
               "label": "Elastic Nginx demo/sample access-log corpus "
                        "(APT-style clients; not production traffic)"},
}

_PARSE_CACHE: dict[str, object] = {}
_SESSION_CACHE: dict[str, list] = {}


def parsed(workload: str):
    """Parsed request table for a workload, cached within a process."""
    if workload not in _PARSE_CACHE:
        spec = WORKLOADS[workload]
        _PARSE_CACHE[workload] = parse_log(str(DATA / spec["file"]), spec["dialect"])
    return _PARSE_CACHE[workload]


def load(workload: str, min_requests: int = MIN_REQUESTS,
         idle: float = IDLE_SECONDS):
    """Sessionise a workload, reusing the cached parse."""
    key = f"{workload}:{min_requests}:{idle}"
    if key not in _SESSION_CACHE:
        _SESSION_CACHE[key] = sessionize(parsed(workload), idle_seconds=idle,
                                              min_requests=min_requests)
    return _SESSION_CACHE[key]


def base_config(seed: int, **kwargs) -> ExperimentConfig:
    """The frozen experiment configuration, with explicit overrides."""
    churn = kwargs.pop("churn", None) or ChurnConfig(
        monotone_rate=kwargs.pop("monotone_rate", MONOTONE_CHURN),
        flapping_rate=kwargs.pop("flapping_rate", FLAPPING_CHURN))
    monitor = kwargs.pop("monitor", None) or MonitorConfig(
        migrate_reference=kwargs.pop("migrate_reference", True),
        evidence=kwargs.pop("evidence", "max"))
    return ExperimentConfig(
        alpha=kwargs.pop("alpha", ALPHA),
        attack_rate=kwargs.pop("attack_rate", ATTACK_RATE),
        attack_fraction=kwargs.pop("attack_fraction", ATTACK_FRACTION),
        earliest_takeover=kwargs.pop("earliest_takeover", 0.25),
        latest_takeover=kwargs.pop("latest_takeover", 0.50),
        theft_delay_s=kwargs.pop("theft_delay_s", None),
        split=kwargs.pop("split", "temporal"),
        weighting=kwargs.pop("weighting", "rarity"),
        seed=seed, churn=churn, monitor=monitor, **kwargs)


def write_table(frame: pd.DataFrame, name: str) -> Path:
    path = TABLES / f"{name}.csv"
    frame.to_csv(path, index=False)
    print(f"  wrote {path.relative_to(ROOT)}  ({len(frame)} rows)")
    return path


def write_meta(obj, name: str) -> Path:
    path = SUMMARY / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, default=str))
    print(f"  wrote {path.relative_to(ROOT)}")
    return path


def summarise(frame: pd.DataFrame, group: list[str], metrics: list[str],
              n_boot: int = 10000) -> pd.DataFrame:
    """Mean, SD and bootstrap 95% CI of each metric within each group."""
    rows = []
    for key, g in frame.groupby(group, sort=True):
        key = key if isinstance(key, tuple) else (key,)
        row = dict(zip(group, key))
        row["n_runs"] = len(g)
        for m in metrics:
            values = g[m].dropna().to_numpy()
            lo, hi = bootstrap_ci(values, n_boot=n_boot)
            row[f"{m}_mean"] = float(values.mean()) if values.size else float("nan")
            row[f"{m}_sd"] = float(values.std(ddof=1)) if values.size > 1 else 0.0
            row[f"{m}_ci_lo"], row[f"{m}_ci_hi"] = lo, hi
        rows.append(row)
    return pd.DataFrame(rows)


class Timer:
    def __init__(self, label: str):
        self.label = label

    def __enter__(self):
        self.t0 = time.perf_counter()
        print(f"== {self.label}")
        return self

    def __exit__(self, *exc):
        print(f"   done in {time.perf_counter() - self.t0:.1f}s")


# ============================================================================
# E0  Corpus audit
# ============================================================================

def corpus_rows() -> pd.DataFrame:
    rows = []
    for key, spec in WORKLOADS.items():
        frame = parsed(key)
        sessions = load(key)
        lens = np.array([s.n for s in sessions])
        span = (frame.ts.max() - frame.ts.min()) / 86400.0
        cores = {parse_user_agent(u)[0::2] for u in frame.ua.unique()}
        rows.append({
            "workload": key,
            "description": spec["label"],
            "source_file": spec["file"],
            "requests_parsed": len(frame),
            "unique_addresses": int(frame.ip.nunique()),
            "unique_scope16": int(frame.ip.map(ip_scope16).nunique()),
            "unique_prefix24": int(frame.ip.map(ip_prefix24).nunique()),
            "unique_user_agents": int(frame.ua.nunique()),
            "unique_agent_cores": len(cores),
            "referrer_coverage": float((frame.referrer.astype(str) != "-").mean()),
            "span_days": round(float(span), 2),
            "sessions": len(sessions),
            "requests_in_sessions": int(lens.sum()),
            "requests_per_session_median": float(np.median(lens)),
            "requests_per_session_mean": round(float(lens.mean()), 2),
            "requests_per_session_p90": float(np.quantile(lens, 0.9)),
            "requests_per_session_max": int(lens.max()),
        })
    return pd.DataFrame(rows)


def sensitivity_rows() -> pd.DataFrame:
    """Session yield as a function of the sessionisation parameters."""
    rows = []
    for key in WORKLOADS:
        for idle in (900.0, 1800.0, 3600.0):
            for min_req in (5, 7, 10, 15):
                sessions = load(key, min_requests=min_req, idle=idle)
                if not sessions:
                    continue
                lens = np.array([s.n for s in sessions])
                rows.append({"workload": key, "idle_seconds": idle,
                             "min_requests": min_req, "sessions": len(sessions),
                             "requests": int(lens.sum()),
                             "median_length": float(np.median(lens))})
    return pd.DataFrame(rows)


def agent_mix() -> pd.DataFrame:
    rows = []
    for key, spec in WORKLOADS.items():
        frame = parsed(key)
        counts = Counter(parse_user_agent(u)[0] for u in frame.ua)
        total = sum(counts.values())
        for browser, n in counts.most_common(6):
            rows.append({"workload": key, "agent_family": browser,
                         "requests": n, "share": round(n / total, 4)})
    return pd.DataFrame(rows)


def run_e0() -> None:
    """E0: corpus statistics, sessionisation sensitivity, agent mix."""
    with Timer("E0 corpus audit"):
        corpus = corpus_rows()
        write_table(corpus, "e0_corpus")
        write_table(sensitivity_rows(), "e0_sessionisation_sensitivity")
        write_table(agent_mix(), "e0_agent_mix")
        write_meta({"idle_seconds": IDLE_SECONDS, "min_requests": MIN_REQUESTS},
                   "e0_sessionisation")
        print(corpus.to_string(index=False))


# ============================================================================
# E1, E1b, E2  Main evaluation, budget sweep and baseline comparison
# ============================================================================

E1_METRICS = ["precision", "recall", "f1", "fpr", "specificity", "balanced_accuracy",
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
                         **{k: m[k] for k in E1_METRICS}})
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


def run_e1() -> None:
    """E1: main result at alpha = 1% over 30 seeds, with per-scenario breakdown."""
    with Timer("E1 main evaluation (30 seeds x 2 workloads)"):
        runs, scen, churn_fp, calib = main_runs()
        write_table(runs, "e1_main_runs")
        write_table(summarise(runs, ["workload"], E1_METRICS), "e1_main_summary")
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
    print("\n--- main summary ---")
    print(summarise(runs, ["workload"],
                    ["recall", "precision", "f1", "fpr", "roc_auc"]).to_string(index=False))


def run_e1b() -> None:
    """E1b: recall and false-alarm rate across the budget grid (15 seeds)."""
    with Timer("E1b false-alarm budget sweep"):
        sweep = alpha_sweep()
        write_table(sweep, "e1_alpha_sweep_runs")
        write_table(summarise(sweep, ["workload", "alpha"],
                              ["recall", "precision", "f1", "fpr", "roc_auc"]),
                    "e1_alpha_sweep")


def run_e2() -> None:
    """E2: SICA against the pinning and scored baselines on identical sessions."""
    with Timer("E2 baseline comparison"):
        base = baseline_runs()
        write_table(base, "e2_baseline_runs")
        write_table(summarise(base, ["workload", "baseline", "family"],
                              ["precision", "recall", "f1", "fpr", "specificity",
                               "balanced_accuracy", "roc_auc", "pr_auc"]),
                    "e2_baselines")


# ============================================================================
# E3  Ablation
# ============================================================================

E3_METRICS = ["precision", "recall", "f1", "fpr", "balanced_accuracy", "roc_auc", "pr_auc"]
SEEDS_ABL = SEEDS[:20]


def _e3_row(workload, seed, family, variant, res):
    m = res["metrics"]
    out = {"workload": workload, "seed": seed, "family": family, "variant": variant,
           "threshold": res["threshold"], **{k: m[k] for k in E3_METRICS}}
    for name in INVARIANTS:
        out[f"w_{name}"] = res["weights"].get(name, 0.0)
    return out


def ablations() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_ABL:
            rows.append(_e3_row(workload, seed, "reference", "full",
                             run_experiment(sessions, base_config(seed))))

            for drop in DEFAULT_INVARIANTS:
                keep = tuple(n for n in DEFAULT_INVARIANTS if n != drop)
                rows.append(_e3_row(workload, seed, "leave_one_out", f"minus_{drop}",
                                 run_experiment(sessions, base_config(seed, enabled=keep))))

            # The invariants that were implemented, evaluated on the development
            # seeds and then rejected: adding each one back to the retained set
            # is reported so that the rejection is auditable rather than asserted.
            rejected = [n for n in INVARIANTS if n not in DEFAULT_INVARIANTS]
            for add in rejected:
                keep = tuple(n for n in INVARIANTS
                             if n in DEFAULT_INVARIANTS or n == add)
                rows.append(_e3_row(workload, seed, "restored", f"plus_{add}",
                                 run_experiment(sessions, base_config(seed, enabled=keep))))
            rows.append(_e3_row(workload, seed, "restored", "plus_all_rejected",
                             run_experiment(sessions, base_config(seed, enabled=INVARIANTS))))

            for only in INVARIANTS:
                try:
                    res = run_experiment(sessions, base_config(seed, enabled=(only,)))
                except ValueError:
                    continue          # invariant not applicable to this workload
                rows.append(_e3_row(workload, seed, "single", f"only_{only}", res))

            rows.append(_e3_row(workload, seed, "weighting", "equal_weights",
                             run_experiment(sessions, base_config(seed, weighting="equal"))))
            rows.append(_e3_row(workload, seed, "design", "no_migration",
                             run_experiment(sessions, base_config(
                                 seed, monitor=MonitorConfig(migrate_reference=False,
                                                             evidence="max")))))
            rows.append(_e3_row(workload, seed, "design", "accumulator",
                             run_experiment(sessions, base_config(
                                 seed, monitor=MonitorConfig(migrate_reference=True,
                                                             evidence="accumulator")))))
    return pd.DataFrame(rows)


def run_e3() -> None:
    """E3: invariant and design ablation (20 seeds)."""
    with Timer("E3 ablation"):
        runs = ablations()
        write_table(runs, "e3_ablation_runs")
        summary = summarise(runs, ["workload", "family", "variant"], E3_METRICS)
        write_table(summary, "e3_ablation")
        print(summary[["workload", "family", "variant", "recall_mean", "fpr_mean",
                       "f1_mean", "roc_auc_mean"]].to_string(index=False))


# ============================================================================
# E4  Robustness (adversary grid, assumption sweeps, crossover)
# ============================================================================

E4_METRICS = ["precision", "recall", "f1", "fpr", "roc_auc",
           "attack_request_detection_rate", "latency_requests_median"]
SEEDS_R = SEEDS[:20]


def _e4_row(workload, seed, factor, value, res, **extra):
    m = res["metrics"]
    return {"workload": workload, "seed": seed, "factor": factor, "value": value,
            "n_attack_sessions": m["n_attack_sessions"],
            **{k: m[k] for k in E4_METRICS}, **extra}


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
                    rows.append(_e4_row(workload, seed, "scenario", f"{level}_{mode}",
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
                rows.append(_e4_row(workload, seed, "flapping_rate", rate, res))
            for rate in (0.0, 0.05, 0.15, 0.30, 0.50):
                res = run_experiment(sessions, base_config(
                    seed, churn=ChurnConfig(monotone_rate=rate, flapping_rate=0.05)))
                rows.append(_e4_row(workload, seed, "monotone_rate", rate, res))
            for frac in (0.05, 0.10, 0.20, 0.40, 0.60):
                res = run_experiment(sessions, base_config(seed, attack_fraction=frac))
                rows.append(_e4_row(workload, seed, "attack_fraction", frac, res))
            for rate in (0.02, 0.05, 0.10, 0.20, 0.35):
                res = run_experiment(sessions, base_config(seed, attack_rate=rate))
                rows.append(_e4_row(workload, seed, "attack_rate", rate, res))
            for lo, hi in ((0.10, 0.20), (0.25, 0.50), (0.50, 0.70), (0.70, 0.85)):
                res = run_experiment(sessions, base_config(
                    seed, earliest_takeover=lo, latest_takeover=hi))
                rows.append(_e4_row(workload, seed, "theft_position", f"{lo:.2f}-{hi:.2f}", res))
            for delay in (0.0, 1.0, 60.0, 600.0):
                res = run_experiment(sessions, base_config(seed, theft_delay_s=delay))
                rows.append(_e4_row(workload, seed, "theft_delay_s", delay, res))
        for min_req in (7, 10, 15, 20):
            subset = load(workload, min_requests=min_req)
            if len(subset) < 60:
                continue
            for seed in SEEDS_R:
                res = run_experiment(subset, base_config(seed))
                rows.append(_e4_row(workload, seed, "min_requests", min_req, res))
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


def run_e4() -> None:
    """E4: adversary grid, assumption sweeps and churn crossover (about 43 minutes)."""
    with Timer("E4a adversary grid"):
        grid, grid_base = scenario_grid()
        write_table(grid, "e4_scenario_grid_runs")
        write_table(summarise(grid, ["workload", "level", "mode"], E4_METRICS),
                    "e4_scenario_grid")
        write_table(grid_base, "e4_scenario_baselines_runs")
        write_table(summarise(grid_base, ["workload", "detector", "level", "mode"],
                              ["recall", "precision", "f1", "fpr"]),
                    "e4_scenario_baselines")

    with Timer("E4b assumption sweeps"):
        sw = sweeps()
        write_table(sw, "e4_sweep_runs")
        write_table(summarise(sw, ["workload", "factor", "value"], E4_METRICS),
                    "e4_sweeps")

    with Timer("E4c address-churn crossover against baselines"):
        cross = churn_crossover()
        write_table(cross, "e4_crossover_runs")
        write_table(summarise(cross, ["workload", "detector", "monotone_rate"],
                              ["precision", "recall", "f1", "fpr", "roc_auc"]),
                    "e4_crossover")

    print(summarise(grid, ["workload", "level", "mode"],
                    ["recall", "fpr"]).to_string(index=False))


# ============================================================================
# E5  Leakage audit
# ============================================================================

SEEDS_L = SEEDS[:20]

FEATURES = {
    "n_requests": lambda s: float(s.n),
    "duration_s": lambda s: float(s.requests[-1].ts - s.requests[0].ts),
    "total_bytes": lambda s: float(sum(r.nbytes for r in s.requests)),
    "mean_bytes": lambda s: float(np.mean([r.nbytes for r in s.requests])),
    "distinct_paths": lambda s: float(len({r.path for r in s.requests})),
    "median_gap_s": lambda s: float(np.median(np.diff([r.ts for r in s.requests]))
                                    if s.n > 1 else 0.0),
    "min_gap_s": lambda s: float(np.min(np.diff([r.ts for r in s.requests]))
                                 if s.n > 1 else 0.0),
    "error_rate": lambda s: float(np.mean([r.status >= 400 for r in s.requests])),
}


def matrix(sessions) -> np.ndarray:
    return np.array([[fn(s) for fn in FEATURES.values()] for s in sessions], dtype=float)


def marginal_audit() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_L:
            res = run_experiment(sessions, base_config(seed))
            ev = res["sessions"]
            y = [s.label for s in ev]
            for name, fn in FEATURES.items():
                rows.append({"workload": workload, "seed": seed, "feature": name,
                             "roc_auc": roc_auc(y, [fn(s) for s in ev])})
    return pd.DataFrame(rows)


def content_reference() -> pd.DataFrame:
    """Mahalanobis-distance outlier score on marginal features, calibrated identically.

    A closed-form, deterministic one-class reference: the calibration split fixes
    a robust mean and covariance, and the session score is the Mahalanobis
    distance from that centre.  It stands in for the family of feature-based
    unsupervised detectors without introducing a fitted model into the proposed
    system.
    """
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for seed in SEEDS_L:
            cfg = base_config(seed)
            res = run_experiment(sessions, cfg)
            cal = matrix(res["calibration_sessions"])
            ev = matrix(res["sessions"])
            y = [s.label for s in res["sessions"]]

            mu = np.median(cal, axis=0)
            centred = cal - mu
            cov = np.cov(centred, rowvar=False) + 1e-6 * np.eye(cal.shape[1])
            inv = np.linalg.pinv(cov)

            def score(x):
                d = x - mu
                return np.sqrt(np.einsum("ij,jk,ik->i", d, inv, d))

            tau = threshold_for_budget(score(cal), cfg.alpha)
            s_ev = score(ev)
            pred = (s_ev >= tau).astype(int)
            c = confusion(y, pred)
            rows.append({"workload": workload, "seed": seed,
                         "detector": "marginal_mahalanobis", **c, **rate_metrics(c),
                         "roc_auc": roc_auc(y, s_ev), "pr_auc": pr_auc(y, s_ev)})
    return pd.DataFrame(rows)


def split_sensitivity() -> pd.DataFrame:
    rows = []
    for workload in WORKLOADS:
        sessions = load(workload)
        for split in ("temporal", "client", "random"):
            for seed in SEEDS_L:
                m = run_experiment(sessions, base_config(seed, split=split))["metrics"]
                rows.append({"workload": workload, "split": split, "seed": seed,
                             **{k: m[k] for k in ["precision", "recall", "f1", "fpr",
                                                  "roc_auc", "pr_auc"]}})
    return pd.DataFrame(rows)


def structural_checks() -> dict:
    """Mechanical leakage checks with an explicit verdict for each."""

    checks = []

    def add(name, passed, detail):
        checks.append({"check": name, "status": "PASS" if passed else "FAIL",
                       "detail": detail})

    for workload in WORKLOADS:
        sessions = load(workload)
        original_length = {s.session_id: s.n for s in sessions}
        ids = [s.session_id for s in sessions]
        add(f"{workload}: session ids unique in corpus",
            len(ids) == len(set(ids)),
            f"{len(ids)} sessions, {len(set(ids))} distinct ids")

        dup_requests = 0
        for s in sessions:
            keys = [(r.ip, r.ua, r.ts, r.path) for r in s.requests]
            dup_requests += len(keys) - len(set(keys))
        add(f"{workload}: duplicate requests within a session",
            True, f"{dup_requests} exact-duplicate request tuples "
                  f"(retained: repeated identical requests occur in real traffic)")

        for seed in (0, 1, 2):
            res = run_experiment(sessions, base_config(seed))
            cal_ids = {s.session_id for s in res["calibration_sessions"]}
            ev_ids = {s.session_id for s in res["sessions"]}
            add(f"{workload} seed {seed}: calibration/evaluation session-disjoint",
                not (cal_ids & ev_ids),
                f"{len(cal_ids & ev_ids)} shared session ids")
            add(f"{workload} seed {seed}: calibration partition attack-free",
                all(s.label == 0 for s in res["calibration_sessions"]) and
                all(r.injected == 0 for s in res["calibration_sessions"]
                    for r in s.requests),
                f"{sum(s.label for s in res['calibration_sessions'])} labelled sessions, "
                f"{sum(r.injected for s in res['calibration_sessions'] for r in s.requests)}"
                " injected requests in calibration")
            add(f"{workload} seed {seed}: injected sessions keep the original length",
                all(s.n == original_length[s.session_id]
                    for s in res["sessions"] if s.label == 1),
                "every injected session has the request count of its original")

        # A client-disjoint split is available and does isolate clients.
        res = run_experiment(sessions, base_config(0, split="client"))
        cal_clients = {s.client for s in res["calibration_sessions"]}
        ev_clients = {s.client for s in res["sessions"]}
        add(f"{workload}: client-disjoint split isolates clients",
            not (cal_clients & ev_clients),
            f"{len(cal_clients & ev_clients)} clients in both partitions")

    add("development and reporting seed blocks are disjoint",
        not (set(SEEDS) & set(DEV_SEEDS)),
        f"reporting {min(SEEDS)}-{max(SEEDS)}, development "
        f"{min(DEV_SEEDS)}-{max(DEV_SEEDS)}")

    timing_free = not ({"V4_transition_velocity", "V5_rate_discontinuity"}
                       & set(DEFAULT_INVARIANTS))
    add("final invariant set consumes no timing or volume feature",
        timing_free,
        "retained invariants: " + ", ".join(DEFAULT_INVARIANTS) +
        " -- none reads an inter-arrival gap, a byte count, a request count or a "
        "session duration, so any residual marginal signal in those quantities "
        "cannot reach the detector")

    return {"checks": checks,
            "n_pass": sum(c["status"] == "PASS" for c in checks),
            "n_fail": sum(c["status"] == "FAIL" for c in checks)}


def run_e5() -> None:
    """E5: marginal features, content reference detector, split sensitivity, structural checks."""
    with Timer("E5a marginal-feature audit"):
        marg = marginal_audit()
        write_table(marg, "e5_marginal_runs")
        write_table(summarise(marg, ["workload", "feature"], ["roc_auc"]),
                    "e5_marginal_audit")

    with Timer("E5b content-feature reference detector"):
        ref = content_reference()
        write_table(ref, "e5_content_reference_runs")
        write_table(summarise(ref, ["workload", "detector"],
                              ["precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]),
                    "e5_content_reference")

    with Timer("E5c split sensitivity"):
        sp = split_sensitivity()
        write_table(sp, "e5_split_runs")
        write_table(summarise(sp, ["workload", "split"],
                              ["precision", "recall", "f1", "fpr", "roc_auc"]),
                    "e5_split_sensitivity")

    with Timer("E5d structural leakage checks"):
        report = structural_checks()
        marg_summary = summarise(marg, ["workload", "feature"], ["roc_auc"])
        report["marginal_feature_auc"] = {
            f"{r.workload}/{r.feature}": round(float(r.roc_auc_mean), 4)
            for r in marg_summary.itertuples()}
        report["content_reference_detector"] = {
            f"{r.workload}": {"roc_auc": round(float(r.roc_auc_mean), 4),
                              "f1": round(float(r.f1_mean), 4)}
            for r in summarise(ref, ["workload"],
                               ["roc_auc", "f1"]).itertuples()}
        report["split_sensitivity_roc_auc"] = {
            f"{r.workload}/{r.split}": round(float(r.roc_auc_mean), 4)
            for r in summarise(sp, ["workload", "split"], ["roc_auc"]).itertuples()}
        write_meta(report, "leakage_report")
        for c in report["checks"]:
            print(f"  [{c['status']}] {c['check']}: {c['detail']}")
        print(f"  {report['n_pass']} passed, {report['n_fail']} failed")

    print(marg_summary.to_string(index=False))


# ============================================================================
# E6  Efficiency
# ============================================================================

REPEATS = 7
WARMUP = 2


def _stream(sessions):
    """Flatten sessions into one globally time-ordered request stream."""
    events = [(r.ts, s.session_id, r.ip, r.ua, r.path, r.referrer)
              for s in sessions for r in s.requests]
    events.sort(key=lambda e: e[0])
    return events


def _deep_size(obj, seen=None) -> int:
    """Recursive resident size of an object and everything it references."""
    seen = seen if seen is not None else set()
    if id(obj) in seen:
        return 0
    seen.add(id(obj))
    size = sys.getsizeof(obj)
    if isinstance(obj, dict):
        size += sum(_deep_size(k, seen) + _deep_size(v, seen) for k, v in obj.items())
    elif isinstance(obj, (list, tuple, set, frozenset)) or type(obj).__name__ == "deque":
        size += sum(_deep_size(v, seen) for v in obj)
    elif hasattr(obj, "__slots__"):
        size += sum(_deep_size(getattr(obj, s), seen)
                    for s in obj.__slots__ if hasattr(obj, s))
    elif hasattr(obj, "__dict__"):
        size += _deep_size(obj.__dict__, seen)
    return size


def throughput(cfg: MonitorConfig, events) -> tuple[float, float, dict]:
    """Uninstrumented timing of the request path. Returns (seconds, req/s, state)."""
    monitor = ContinuityMonitor(cfg)
    observe = monitor.observe
    gc.disable()
    try:
        t0 = time.perf_counter()
        for ts, sid, ip, ua, path, ref in events:
            observe(sid, ip, ua, ts, path, ref)
        elapsed = time.perf_counter() - t0
    finally:
        gc.enable()
    state = {"live_sessions": len(monitor.sessions),
             "state_bytes_per_session":
                 _deep_size(monitor.sessions) / max(1, len(monitor.sessions))}
    return elapsed, len(events) / elapsed, state


def latency_percentiles(cfg: MonitorConfig, events) -> dict:
    """Per-call timing. Absolute values include the timer overhead they measure."""
    monitor = ContinuityMonitor(cfg)
    observe = monitor.observe
    per = np.empty(len(events), dtype=float)
    gc.disable()
    try:
        for i, (ts, sid, ip, ua, path, ref) in enumerate(events):
            a = time.perf_counter()
            observe(sid, ip, ua, ts, path, ref)
            per[i] = time.perf_counter() - a
    finally:
        gc.enable()
    return {"latency_us_median": 1e6 * float(np.median(per)),
            "latency_us_p95": 1e6 * float(np.quantile(per, 0.95)),
            "latency_us_p99": 1e6 * float(np.quantile(per, 0.99)),
            "latency_us_max": 1e6 * float(per.max())}


def measure(cfg: MonitorConfig, events) -> dict:
    for _ in range(WARMUP):
        throughput(cfg, events)
    runs = [throughput(cfg, events) for _ in range(REPEATS)]
    tputs = [r[1] for r in runs]
    lat = [latency_percentiles(cfg, events) for _ in range(3)]
    return {"requests": len(events),
            "live_sessions": runs[0][2]["live_sessions"],
            "throughput_req_per_s": float(np.median(tputs)),
            "throughput_req_per_s_min": float(np.min(tputs)),
            "throughput_req_per_s_max": float(np.max(tputs)),
            "us_per_request_uninstrumented":
                1e6 * float(np.median([r[0] for r in runs])) / max(1, len(events)),
            **{k: float(np.median([d[k] for d in lat])) for k in lat[0]},
            "state_bytes_per_session": float(np.median(
                [r[2]["state_bytes_per_session"] for r in runs]))}


def scaling(cfg: MonitorConfig, events) -> pd.DataFrame:
    """Per-request cost as the number of concurrently live sessions grows."""
    ids = sorted({e[1] for e in events})
    rows = []
    for share in (0.05, 0.1, 0.25, 0.5, 1.0):
        keep = set(ids[: max(1, int(share * len(ids)))])
        subset = [e for e in events if e[1] in keep]
        if len(subset) < 50:
            continue
        rows.append(measure(cfg, subset))
    return pd.DataFrame(rows)


def preparation_cost() -> pd.DataFrame:
    """Offline log parsing and sessionisation, timed separately from detection."""
    rows = []
    for workload in WORKLOADS:
        t0 = time.perf_counter()
        frame = parsed(workload)
        parse_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        sessions = load(workload)
        sess_s = time.perf_counter() - t0
        rows.append({"workload": workload, "requests": len(frame),
                     "parse_seconds": parse_s, "sessionise_seconds": sess_s,
                     "parse_us_per_request": 1e6 * parse_s / max(1, len(frame))})
    return pd.DataFrame(rows)


def run_e6() -> None:
    """E6: throughput, latency, scaling and memory of the detector."""
    rows, scale_rows = [], []
    with Timer("E6 efficiency"):
        prep = preparation_cost()      # also warms the caches used below
        for workload in WORKLOADS:
            sessions = load(workload)
            res = run_experiment(sessions, base_config(0))
            cfg = res["monitor_cfg"]
            events = _stream(res["sessions"])

            row = {"workload": workload, "invariants": len(cfg.enabled), **measure(cfg, events)}
            first = res["sessions"][0].requests[0]
            row["state_bytes_design_bound"] = SessionState(
                binding_of(first.ip, first.ua), (), 0.0
            ).nbytes(cfg.ring_size, cfg.path_window)
            rows.append(row)

            sc = scaling(cfg, events)
            sc.insert(0, "workload", workload)
            scale_rows.append(sc)

        write_table(pd.DataFrame(rows), "e6_efficiency")
        write_table(pd.concat(scale_rows, ignore_index=True), "e6_scaling")
        write_table(prep, "e6_preparation_cost")
        write_meta({
            "repeats": REPEATS, "warmup_runs": WARMUP,
            "aggregation": "median over repeats",
            "gc": "disabled during timed loops",
            "throughput_method": "uninstrumented loop over pre-parsed requests",
            "latency_method": "per-call perf_counter; includes timer overhead",
            "complexity_time": "O(1) per request: bounded agent parse, three prefix "
                               "comparisons, a ring membership test (|ring|=4), a "
                               "hash-set membership test, and an EWMA update",
            "complexity_memory": "O(1) per live session; O(S) for S live sessions",
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "numpy": np.__version__, "pandas": pd.__version__,
        }, "e6_environment")
        print(pd.DataFrame(rows).to_string(index=False))


# ============================================================================
# E7  Statistical tests and base rates
# ============================================================================

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


def run_e7() -> None:
    """E7: paired Wilcoxon tests (Holm) and base-rate table."""
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


# ============================================================================
# Development studies (seeds 100-119, not reported)
# ============================================================================

DEV_SEEDS = tuple(range(100, 120))

def run_dev_design() -> None:
    """Development: evidence rule, reference migration and budget on seeds 100-119."""
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
DEV_METRICS = ["precision", "recall", "f1", "fpr", "roc_auc", "pr_auc"]

def run_dev_invariants() -> None:
    """Development: choice of the invariant set on seeds 100-119."""
    rows = []
    with Timer("development invariant-set study (seeds 100-119)"):
        for workload in WORKLOADS:
            sessions = load(workload)
            for name, enabled in CANDIDATES.items():
                for seed in DEV_SEEDS:
                    m = run_experiment(sessions, base_config(seed, enabled=enabled))["metrics"]
                    rows.append({"workload": workload, "variant": name, "seed": seed,
                                 **{k: m[k] for k in DEV_METRICS}})
        d = pd.DataFrame(rows)
        write_table(d, "dev_invariants_runs")
        s = summarise(d, ["workload", "variant"], DEV_METRICS)
        write_table(s, "dev_invariants")
        print(s[["workload", "variant", "recall_mean", "precision_mean", "f1_mean",
                 "fpr_mean", "roc_auc_mean", "pr_auc_mean"]].round(4).to_string(index=False))


# ============================================================================
# Per-session decisions (one worked example of the final ALLOW / ALERT output)
# ============================================================================

def run_decisions(seed: int = 0) -> None:
    """Write the SICA decision for every evaluation session of one seed.

    This is the detector's final output in readable form: each session's peak
    risk, the calibrated threshold, ALLOW or ALERT, and which invariants fired
    at the peak.  It uses the same run as seed 0 of E1, so it adds no result.
    """
    with Timer(f"per-session decisions (seed {seed})"):
        rows = []
        for workload in WORKLOADS:
            res = run_experiment(load(workload), base_config(seed))
            tau = res["threshold"]
            peak, first_alert = {}, {}
            for r in res["records"]:
                sid = r["session_id"]
                if sid not in peak or r["risk"] > peak[sid]["risk"]:
                    peak[sid] = r
                if r["risk"] >= tau and sid not in first_alert:
                    first_alert[sid] = r["request_index"]
            for s in res["sessions"]:
                r = peak.get(s.session_id)
                risk = r["risk"] if r else 0.0
                rows.append({
                    "workload": workload, "seed": seed, "session_id": s.session_id,
                    "n_requests": s.n,
                    "truth": "hijacked" if s.label else "benign",
                    "scenario": s.scenario,
                    "peak_risk": round(risk, 6), "threshold": round(tau, 6),
                    "decision": decision(risk, tau),
                    "alert_at_request": first_alert.get(s.session_id, ""),
                    "fired_at_peak": r["explanation"] if r else "",
                })
        frame = pd.DataFrame(rows)
        path = SUMMARY / f"decisions_seed{seed}.csv"
        frame.to_csv(path, index=False)
        print(f"  wrote {path.relative_to(ROOT)}  ({len(frame)} sessions)")
