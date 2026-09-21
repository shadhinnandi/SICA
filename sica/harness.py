"""End-to-end experiment harness: split, inject, calibrate, evaluate.

Protocol (fixed for every experiment in this study)
---------------------------------------------------
1. Real access-log traffic is sessionised into client sessions.
2. Sessions are split into a **calibration** and an **evaluation** partition.
   The default split is *temporal*: the earliest sessions calibrate, the latest
   are evaluated.  ``client`` (client-disjoint) and ``random`` splits are
   available and are reported as leakage controls.
3. Attacks are injected **only** into evaluation sessions, so the calibration
   partition is attack-free by construction.
4. Invariant weights and the operating threshold are derived from the
   calibration partition alone and are frozen.
5. Evaluation sessions are replayed through the frozen monitor.
6. Ground-truth labels are read only to compute metrics, after every decision
   has been produced.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .baselines import PINNING_BASELINES, SCORED_BASELINES, pinning_predictions, session_scores
from .calibrate import calibrate, threshold_for_budget
from .churn import ChurnConfig, apply_churn
from .inject import LEVELS_ALL, MODES, InjectionConfig, build_donor_pool, inject_session
from .invariants import DEFAULT_INVARIANTS, INVARIANTS
from .metrics import (confusion, evaluate_sessions, index_records, pr_auc,
                      rate_metrics, roc_auc)
from .monitor import ContinuityMonitor, MonitorConfig

__all__ = ["ExperimentConfig", "split_sessions", "inject_mixture", "run_experiment",
           "run_baselines"]


@dataclass
class ExperimentConfig:
    alpha: float = 0.01                       # session-level false-alarm budget
    attack_rate: float = 0.20                 # share of evaluation sessions targeted
    split: str = "temporal"                   # temporal | client | random
    calibration_share: float = 0.5
    weighting: str = "rarity"                 # rarity | equal
    enabled: tuple[str, ...] = DEFAULT_INVARIANTS
    # The reported envelope spans the address-visible levels L0-L3 *and* the co-located
    # levels L4/L5.  Restricting it to L0-L3 would give any address-pinning rule perfect
    # recall by construction and would reduce the benchmark to address-change detection.
    levels: tuple[str, ...] = LEVELS_ALL
    modes: tuple[str, ...] = MODES
    attack_fraction: float = 0.4
    earliest_takeover: float = 0.25
    latest_takeover: float = 0.50
    theft_delay_s: float | None = None
    seed: int = 0
    churn: ChurnConfig = field(default_factory=ChurnConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------

def split_sessions(sessions, cfg: ExperimentConfig):
    """Partition sessions into calibration and evaluation sets."""
    rng = np.random.default_rng(cfg.seed)
    if cfg.split == "temporal":
        ordered = sorted(sessions, key=lambda s: s.requests[0].ts)
        cut = int(round(cfg.calibration_share * len(ordered)))
        return ordered[:cut], ordered[cut:]
    if cfg.split == "client":
        clients = sorted({s.client for s in sessions})
        idx = rng.permutation(len(clients))
        cut = int(round(cfg.calibration_share * len(clients)))
        cal_clients = {clients[int(i)] for i in idx[:cut]}
        cal = [s for s in sessions if s.client in cal_clients]
        ev = [s for s in sessions if s.client not in cal_clients]
        return cal, ev
    if cfg.split == "random":
        idx = rng.permutation(len(sessions))
        cut = int(round(cfg.calibration_share * len(sessions)))
        return ([sessions[int(i)] for i in idx[:cut]],
                [sessions[int(i)] for i in idx[cut:]])
    raise ValueError(f"unknown split: {cfg.split}")


# ---------------------------------------------------------------------------
# Injection over a scenario mixture
# ---------------------------------------------------------------------------

def inject_mixture(evaluation, cfg: ExperimentConfig, rng: np.random.Generator):
    """Inject attacks drawn uniformly from the configured scenario grid."""
    donors = build_donor_pool(evaluation, min_len=3)
    grid = [(lv, md) for lv in cfg.levels for md in cfg.modes]
    reasons: dict[str, int] = {}
    out, stats = [], {"targeted": 0, "injected": 0, "per_scenario": {},
                      "refused_per_scenario": {}}
    target = rng.random(len(evaluation)) < cfg.attack_rate
    for i, s in enumerate(evaluation):
        if not target[i]:
            out.append(s)
            continue
        lv, md = grid[int(rng.integers(0, len(grid)))]
        stats["targeted"] += 1
        key = f"{lv}_{md}"
        made = inject_session(
            s, donors,
            InjectionConfig(level=lv, mode=md, attack_fraction=cfg.attack_fraction,
                            earliest_takeover=cfg.earliest_takeover,
                            latest_takeover=cfg.latest_takeover,
                            theft_delay_s=cfg.theft_delay_s),
            rng, reasons=reasons)
        if made is None:
            # The requested condition could not be realised for this victim.  It is counted
            # per scenario so that the *effective* experimental condition is reported: a
            # theft window that a workload's session lengths cannot supply shows up here
            # rather than being silently replaced by a different theft point.
            out.append(s)
            stats["refused_per_scenario"][key] = \
                stats["refused_per_scenario"].get(key, 0) + 1
        else:
            out.append(made)
            stats["injected"] += 1
            stats["per_scenario"][key] = stats["per_scenario"].get(key, 0) + 1
    stats["n_evaluation_sessions"] = len(out)
    stats["attack_prevalence"] = stats["injected"] / max(1, len(out))
    stats["refusal_reasons"] = reasons
    stats["theft_window"] = [cfg.earliest_takeover, cfg.latest_takeover]
    return out, stats


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def _replay(sessions, monitor_cfg: MonitorConfig) -> list[dict]:
    monitor = ContinuityMonitor(monitor_cfg)
    out = []
    for s in sessions:
        for r in s.requests:
            out.append(monitor.observe(s.session_id, r.ip, r.ua, r.ts,
                                       r.path, r.referrer))
    return out


def run_experiment(sessions, cfg: ExperimentConfig) -> dict:
    """Execute one complete calibrate-then-evaluate run and return all outputs."""
    rng = np.random.default_rng(cfg.seed)
    cal, ev = split_sessions(sessions, cfg)
    if len(cal) < 20 or len(ev) < 20:
        raise ValueError("split produced too few sessions to calibrate or evaluate")

    # Benign binding churn is applied to BOTH partitions with the same declared
    # rates: the calibration traffic an operator would use is itself subject to
    # legitimate mobility, so the false-alarm budget must be met in its presence.
    cal, cal_churn = apply_churn(cal, cfg.churn, rng)
    ev, ev_churn = apply_churn(ev, cfg.churn, rng)

    ev_injected, inj_stats = inject_mixture(ev, cfg, rng)

    monitor_cfg, cal_info = calibrate(
        cal, alpha=cfg.alpha, enabled=cfg.enabled, weighting=cfg.weighting,
        base_cfg=cfg.monitor)

    records = _replay(ev_injected, monitor_cfg)
    idx = index_records(records)
    result = evaluate_sessions(ev_injected, records, monitor_cfg.threshold, index=idx)

    # Per-scenario breakdown, evaluated against the shared benign population so
    # that precision and FPR remain interpretable in every cell.
    benign = [s for s in ev_injected if s.label == 0]
    by_scenario: dict[str, list] = {}
    for s in ev_injected:
        if s.label == 1:
            by_scenario.setdefault(s.scenario, []).append(s)
    per_scenario = {}
    for scenario in sorted(by_scenario):
        subset = benign + by_scenario[scenario]
        per_scenario[scenario] = evaluate_sessions(subset, records,
                                                   monitor_cfg.threshold, index=idx)

    # Benign false alarms broken down by the legitimate churn phenomenon that
    # caused them, so that the cost of each invariant on real mobility is visible.
    fp_by_churn: dict[str, dict] = {}
    peak = {sid: max((r["risk"] for r in rs), default=0.0) for sid, rs in idx.items()}
    for s in ev_injected:
        if s.label != 0:
            continue
        row = fp_by_churn.setdefault(s.scenario, {"sessions": 0, "false_alarms": 0})
        row["sessions"] += 1
        row["false_alarms"] += int(peak.get(s.session_id, 0.0) >= monitor_cfg.threshold)
    for row in fp_by_churn.values():
        row["fpr"] = row["false_alarms"] / max(1, row["sessions"])

    return {"metrics": result, "per_scenario": per_scenario,
            "fp_by_churn": fp_by_churn,
            "churn": {"calibration": cal_churn, "evaluation": ev_churn},
            "calibration": cal_info, "injection": inj_stats,
            "n_calibration_sessions": len(cal), "n_evaluation_sessions": len(ev_injected),
            "threshold": monitor_cfg.threshold, "weights": monitor_cfg.weights,
            "sessions": ev_injected, "records": records, "monitor_cfg": monitor_cfg,
            "calibration_sessions": cal}


def run_baselines(cal_sessions, ev_sessions, alpha: float) -> list[dict]:
    """Evaluate every baseline on the same evaluation sessions.

    Pinning rules are parameter-free.  Scored rules are calibrated to the same
    false-alarm budget on the same attack-free calibration partition.

    **Reporting treatment of binary rules.**  A pinning rule emits a decision, not a score:
    it has one operating point and no ranking to measure.  Its ROC curve therefore has a
    single interior point and the area under it collapses identically to
    ``(TPR + TNR) / 2`` --- balanced accuracy --- which
    ``tests/test_regressions.py::test_binary_rule_auc_is_exactly_balanced_accuracy``
    asserts.  Reporting that quantity in the same ``roc_auc`` column as a ranking AUC over a
    continuous risk score would imply a score resolution the rule does not have, and would
    invite a comparison that is not meaningful.  So ranking metrics are withheld for these
    rules (``NaN``) and their operating-point metrics --- recall, FPR, precision, F1,
    balanced accuracy --- carry the comparison instead.  No continuous score is invented for
    them: none exists.  ``score_resolution`` marks which treatment each row received, so the
    distinction survives into every generated table.
    """
    y = [s.label for s in ev_sessions]
    rows = []
    for name in PINNING_BASELINES:
        pred = pinning_predictions(ev_sessions, name)
        c = confusion(y, pred)
        rows.append({"baseline": name, "family": "pinning", "threshold": float("nan"),
                     "score_resolution": "binary",
                     **c, **rate_metrics(c),
                     "roc_auc": float("nan"), "pr_auc": float("nan")})
    for name in SCORED_BASELINES:
        cal_scores = session_scores(cal_sessions, name)
        tau = threshold_for_budget(cal_scores, alpha)
        ev_scores = session_scores(ev_sessions, name)
        pred = (ev_scores >= tau).astype(int)
        c = confusion(y, pred)
        rows.append({"baseline": name, "family": "scored", "threshold": float(tau),
                     "score_resolution": "continuous",
                     **c, **rate_metrics(c),
                     "roc_auc": roc_auc(y, ev_scores), "pr_auc": pr_auc(y, ev_scores)})
    return rows
