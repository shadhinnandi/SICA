"""Label-free calibration of invariant weights and of the operating threshold.

Both quantities are derived exclusively from *attack-free* calibration traffic.
No attack label, and no observation from the evaluation split, is read at any
point in this module.  This is the property whose absence invalidated the
project's earlier threshold analysis.

Weighting
---------
An invariant that fires often on benign traffic carries little information when
it fires; one that almost never fires on benign traffic carries a great deal.
Weights are therefore inversely proportional to the invariant's benign firing
mass,

.. math::  w_i \\propto \\frac{1}{\\varepsilon_i + \\varepsilon_0},
    \\qquad \\varepsilon_i = \\frac{1}{|C|}\\sum_{r \\in C} v_i(r),

where :math:`C` is the calibration request set and :math:`\\varepsilon_0` is a
fixed floor that bounds the weight of an invariant that never fires.  This is
a benign-rarity prior, not a fit: it uses no attack data and has no free
parameter beyond the declared floor.

Threshold
---------
The operating threshold is the :math:`(1-\\alpha)` quantile of *session* peak
risk over the calibration split, where :math:`\\alpha` is the operator's
session-level false-alarm budget.  The threshold is frozen before any
evaluation session is scored.
"""
from __future__ import annotations

import numpy as np

from .invariants import DEFAULT_INVARIANTS, INVARIANTS
from .monitor import ContinuityMonitor, MonitorConfig

__all__ = ["EPSILON_FLOOR", "APPLICABILITY_FLOOR", "applicability",
           "benign_rarity_weights", "session_peak_risks", "threshold_for_budget",
           "calibrate", "derive_site_hosts"]

EPSILON_FLOOR = 0.01
APPLICABILITY_FLOOR = 0.01  # an invariant must be exercisable on >=1% of requests


def applicability(records: list[dict], enabled=DEFAULT_INVARIANTS) -> dict[str, float]:
    """Share of calibration requests in which each invariant's precondition held.

    An invariant whose precondition is never exercised --- a referrer rule on a
    workload that carries no referrers, an agent rule where no agent is logged
    --- is not a strong invariant that happens never to fire; it is one that
    cannot fire.  Distinguishing the two is essential, because a rarity prior
    would otherwise award such an invariant the largest possible weight and
    dilute every invariant that is actually observable.
    """
    return {name: float(np.mean([r[f"A_{name}"] for r in records])) for name in enabled}


def benign_rarity_weights(records: list[dict], enabled=DEFAULT_INVARIANTS,
                          floor: float = EPSILON_FLOOR) -> dict[str, float]:
    """Surprisal weighting by benign firing mass, restricted to applicable invariants.

    .. math:: w_i \\propto \\log\\!\\big(1/(\\varepsilon_i + \\varepsilon_0)\\big)

    The logarithm is the self-information of the invariant firing under the
    benign model.  It is used in preference to :math:`1/\\varepsilon_i` because
    the reciprocal is unbounded as :math:`\\varepsilon_i \\to 0` and lets a single
    quiet invariant dominate the score.
    """
    if not records:
        raise ValueError("calibration record set is empty")
    arr = {name: float(np.mean([r[name] for r in records])) for name in enabled}
    raw = {name: float(np.log(1.0 / (arr[name] + floor))) for name in enabled}
    total = sum(raw.values())
    return {name: raw[name] / total for name in enabled}


def benign_firing_rates(records: list[dict], enabled=DEFAULT_INVARIANTS) -> dict[str, float]:
    """Mean benign violation degree per invariant (the :math:`\\varepsilon_i`)."""
    return {name: float(np.mean([r[name] for r in records])) for name in enabled}


def session_peak_risks(records: list[dict]) -> dict[str, float]:
    """Maximum per-request risk within each session."""
    peak: dict[str, float] = {}
    for r in records:
        sid = r["session_id"]
        if r["risk"] > peak.get(sid, -1.0):
            peak[sid] = r["risk"]
    return peak


def threshold_for_budget(peaks, alpha: float) -> float:
    """Smallest threshold meeting a session-level false-alarm budget ``alpha``.

    **Calibration population.**  ``peaks`` is the session peak risk of every session in the
    attack-free calibration partition, computed through the same evidence pipeline that
    evaluation uses.  No evaluation session and no label contributes to it.

    **Alert inequality.**  The monitor alerts on ``peak >= tau``.  The threshold must
    therefore be chosen against that exact inequality; a bound derived for ``>`` does not
    transfer.

    **Tie handling, and why a quantile is not enough.**  The risk statistic is a weighted sum
    of a few invariants with fixed severities, so it is coarse: it takes a small number of
    distinct values and the calibration population is heavily tied on them.  Taking the
    ``(1 - alpha)`` quantile lands on a plateau of tied values, and ``>=`` then admits the
    *entire* plateau.  The previous implementation did exactly this and overshot its budget
    by a factor of two to four on real traffic (measured: 2.15% and 1.85% against a 1.0%
    budget, and 3.9% on one seed).  Because only an observed value can change the alarm set,
    the admissible thresholds are exactly the distinct observed values; this function scans
    them and returns the smallest one whose realised alarm rate satisfies the budget.

    **Guarantee.**  The returned ``tau`` satisfies ``mean(peaks >= tau) <= alpha``, and no
    smaller observed value does.  Minimality matters: the budget could otherwise be met
    trivially by thresholding above every observation and detecting nothing.

    **Finite-sample behaviour.**  Achievable alarm rates are multiples of ``1/N`` for ``N``
    calibration sessions, so a budget below ``1/N`` is attainable only by alerting on
    nothing.  When no observed value meets the budget --- including when more than
    ``alpha * N`` sessions are tied at the maximum --- the conservative choice is taken and
    ``tau`` is placed just above the maximum, which alerts on nothing.  The realised rate is
    recorded as ``calibration_alarm_rate`` by :func:`calibrate`, so the achieved value is
    always reported rather than assumed.
    """
    values = np.asarray(list(peaks), dtype=float)
    if values.size == 0:
        raise ValueError("no calibration sessions")
    if alpha <= 0.0:
        return float(np.nextafter(values.max(), np.inf))

    n = values.size
    ordered = np.sort(values)
    distinct = np.unique(values)[::-1]              # descending candidates
    # |{p : p >= v}| for each candidate v, i.e. the alarm set this threshold admits.
    admitted = n - np.searchsorted(ordered, distinct, side="left")
    budget = alpha * n + 1e-9
    # ``admitted`` is non-decreasing down the descending scan, so the admissible candidates
    # form a prefix and the last of them is the smallest qualifying threshold.
    ok = np.flatnonzero(admitted <= budget)
    if ok.size == 0:
        return float(np.nextafter(values.max(), np.inf))
    return float(distinct[int(ok[-1])])


def derive_site_hosts(sessions, min_share: float = 0.05) -> frozenset[str]:
    """Identify the first-party hosts of the monitored application.

    Access logs do not record the served host, so it is inferred from the
    calibration traffic alone: hosts that account for at least ``min_share`` of
    all non-empty ``Referer`` values are treated as first-party.  This is a
    corpus-level constant derived from attack-free data and frozen with the rest
    of the configuration.
    """
    from .invariants import referrer_path
    counts: dict[str, int] = {}
    total = 0
    for s in sessions:
        for r in s.requests:
            host, _ = referrer_path(r.referrer)
            if host:
                counts[host] = counts.get(host, 0) + 1
                total += 1
    if total == 0:
        return frozenset()
    return frozenset(h for h, c in counts.items() if c / total >= min_share)


def _replay(sessions, cfg: MonitorConfig) -> list[dict]:
    monitor = ContinuityMonitor(cfg)
    out = []
    for s in sessions:
        for i, r in enumerate(s.requests):
            out.append(monitor.observe(s.session_id, r.ip, r.ua, r.ts,
                                       r.path, r.referrer))
    return out


def calibrate(calibration_sessions, alpha: float = 0.01,
              enabled=DEFAULT_INVARIANTS, weighting: str = "rarity",
              base_cfg: MonitorConfig | None = None) -> tuple[MonitorConfig, dict]:
    """Derive weights and threshold from attack-free calibration sessions.

    Two passes over the calibration traffic are required and no more.  The first
    replays it with unit weights to obtain each invariant's benign firing mass,
    from which the weights follow.  The second replays it with those weights
    through the *same* evidence pipeline that evaluation will use --- including
    reference migration and the evidence accumulator --- so that the quantile is
    taken over exactly the statistic that will later be thresholded.  Calibrating
    on a different statistic than the one deployed silently breaks the budget.

    ``weighting`` is ``"rarity"`` for the benign-rarity prior or ``"equal"`` for
    the uniform control.
    """
    base = base_cfg or MonitorConfig()
    site_hosts = derive_site_hosts(calibration_sessions)

    def make(weights: dict[str, float], threshold: float) -> MonitorConfig:
        return MonitorConfig(weights=weights, threshold=threshold, params=base.params,
                             ring_size=base.ring_size, path_window=base.path_window,
                             site_hosts=site_hosts, enabled=tuple(enabled),
                             migrate_reference=base.migrate_reference,
                             evidence=base.evidence, decay=base.decay)

    # Pass 1: invariant firing mass on benign traffic.  The probe evaluates every
    # implemented invariant, not only the enabled ones, so that the firing rate
    # and applicability of a rejected invariant remain observable in the
    # calibration record even when it is not part of the deployed set.
    probe = make({n: 1.0 for n in INVARIANTS}, float("inf"))
    probe.enabled = tuple(INVARIANTS)
    records = [r for r in _replay(calibration_sessions, probe) if not r["established"]]
    if not records:
        raise ValueError("calibration traffic contains no post-establishment requests")
    rates = benign_firing_rates(records, INVARIANTS)
    applic = applicability(records, INVARIANTS)
    active = tuple(n for n in enabled if applic[n] >= APPLICABILITY_FLOOR)
    if not active:
        raise ValueError("no invariant is applicable to this workload")
    if weighting == "rarity":
        weights = benign_rarity_weights(records, active)
    elif weighting == "equal":
        weights = {n: 1.0 / len(active) for n in active}
    else:
        raise ValueError(f"unknown weighting: {weighting}")
    enabled = active

    # Pass 2: the deployed statistic, under the deployed weights.
    scored = _replay(calibration_sessions, make(weights, float("inf")))
    peak: dict[str, float] = {}
    for r in scored:
        if r["established"]:
            continue
        sid = r["session_id"]
        if r["risk"] > peak.get(sid, -1.0):
            peak[sid] = float(r["risk"])
    tau = threshold_for_budget(peak.values(), alpha)

    cfg = make(weights, tau)
    info = {"alpha": alpha, "threshold": tau, "weighting": weighting,
            "site_hosts": sorted(site_hosts),
            "evidence": base.evidence, "decay": base.decay,
            "migrate_reference": base.migrate_reference,
            "n_calibration_sessions": len(peak),
            "n_calibration_requests": len(records),
            "calibration_alarm_rate": float(
                sum(1 for v in peak.values() if v >= tau) / max(1, len(peak))),
            "benign_firing_rate": rates, "applicability": applic,
            "active_invariants": list(active), "weights": weights}
    return cfg, info
