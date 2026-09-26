"""SICA detector: session state, risk score, threshold calibration and decision.

One call to ``ContinuityMonitor.observe`` processes one request:

    binding_of(ip, user_agent)                     (fingerprint.py)
      -> V1 agent mutation, V2 scope discontinuity,
         V3 binding fork                           (invariants.py)
      -> risk = sum_i w_i * v_i
      -> session peak risk >= tau ?  ALERT : ALLOW

The weights ``w_i`` and the threshold ``tau`` come from :func:`calibrate`, which
reads attack-free calibration sessions only:

* ``w_i`` is proportional to ``log(1 / (eps_i + 0.01))``, where ``eps_i`` is the
  mean benign violation degree of invariant ``i`` (rare on benign traffic means
  informative when it fires).  An invariant exercisable on fewer than 1% of
  calibration requests is dropped (applicability gate).
* ``tau`` is the smallest observed calibration session peak risk whose alarm
  rate is at most ``alpha`` (the false-alarm budget, 1% by default).

Cost: O(1) time per request and O(1) state per live session.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import numpy as np

from .fingerprint import Binding, binding_of
from .invariants import (
    DEFAULT_INVARIANTS,
    INVARIANTS,
    InvariantParams,
    referrer_path,
    v1_agent_mutation,
    v2_scope_discontinuity,
    v3_binding_fork,
    v4_transition_velocity,
    v5_rate_discontinuity,
    v6_navigation_break,
)

__all__ = ["SessionState", "MonitorConfig", "ContinuityMonitor", "EQUAL_WEIGHTS",
           "decision", "EPSILON_FLOOR", "APPLICABILITY_FLOOR", "applicability",
           "benign_rarity_weights", "benign_firing_rates", "session_peak_risks",
           "threshold_for_budget", "derive_site_hosts", "calibrate"]


def decision(peak_risk: float, threshold: float) -> str:
    """Final session decision: ALERT when the peak risk reaches the threshold."""
    return "ALERT" if peak_risk >= threshold else "ALLOW"


# ============================================================================
# Per-session state and the request-level monitor
# ============================================================================

EQUAL_WEIGHTS: dict[str, float] = {name: 1.0 / len(INVARIANTS) for name in INVARIANTS}


@dataclass
class MonitorConfig:
    """Frozen configuration of the monitor."""

    weights: dict[str, float] = field(default_factory=lambda: dict(EQUAL_WEIGHTS))
    threshold: float = 1.0            # risk at or above which a session is alerted
    params: InvariantParams = field(default_factory=InvariantParams)
    ring_size: int = 4                # distinct bindings remembered per session
    path_window: int = 32             # in-session URLs remembered for V6
    site_hosts: frozenset = frozenset()     # first-party hosts, derived at calibration
    enabled: tuple[str, ...] = DEFAULT_INVARIANTS   # active set (INVARIANTS for ablation)
    migrate_reference: bool = True          # re-pin after a monotone transition
    evidence: str = "max"                   # "max" | "accumulator"
    decay: float = 0.6                      # accumulator retention per request

    def normalised_weights(self) -> dict[str, float]:
        active = {k: float(self.weights.get(k, 0.0)) for k in self.enabled}
        total = sum(active.values())
        if total <= 0:
            raise ValueError("at least one enabled invariant must carry positive weight")
        return {k: v / total for k, v in active.items()}


@dataclass(slots=True)
class SessionState:
    """Bounded state carried for one live session."""

    pinned: Binding
    last_key: tuple
    last_ts: float
    n_seen: int = 1
    ewma_gap: float | None = None
    ring: deque = field(default_factory=deque)          # bounded, distinct binding keys
    paths: deque = field(default_factory=deque)         # bounded, recent in-session URLs
    path_set: set = field(default_factory=set)          # membership index over ``paths``
    accumulator: float = 0.0
    peak_risk: float = 0.0
    evidence_peak: float = 0.0
    alerted_at: int | None = None                       # request index of first alert

    def nbytes(self, ring_size: int, path_window: int, path_bytes: int = 48) -> int:
        """Analytic upper bound on the bytes held for this session.

        Counted as: pinned binding (6 short strings), last binding key, two
        timestamps, three counters, the bounded binding ring and the bounded
        path window.  Used by the efficiency experiment as the *design* bound;
        the measured resident cost is reported alongside it.
        """
        binding_bytes = 6 * 16
        scalar_bytes = 8 * 6
        return (binding_bytes + scalar_bytes
                + ring_size * 5 * 16
                + path_window * path_bytes)


class ContinuityMonitor:
    """Evaluate session-continuity invariants over a stream of requests."""

    def __init__(self, config: MonitorConfig | None = None) -> None:
        self.cfg = config or MonitorConfig()
        self._w = self.cfg.normalised_weights()
        self._on = {name: name in self.cfg.enabled for name in INVARIANTS}
        self._ZERO = {name: 0.0 for name in INVARIANTS}
        self._FALSE = {name: False for name in INVARIANTS}
        self.sessions: dict[str, SessionState] = {}

    # -- state -------------------------------------------------------------
    def reset(self) -> None:
        self.sessions.clear()

    def _remember_path(self, st: SessionState, path: str | None) -> None:
        """Record a request path in the bounded window, keeping the index in step.

        The deque bounds the memory; the parallel set makes the membership test
        that ``v_6`` performs a constant-time lookup rather than a rebuild of a
        32-element set on every request.  A path is normalised to its path
        component so that it is comparable with a normalised ``Referer``; without
        this a request logged with a query string could never match the referrer
        that pointed at it.
        """
        if not path:
            return
        clean = str(path).split("?", 1)[0].split("#", 1)[0]
        if len(st.paths) >= self.cfg.path_window:
            evicted = st.paths.popleft()
            if evicted not in st.paths:
                st.path_set.discard(evicted)
        st.paths.append(clean)
        st.path_set.add(clean)

    # -- core --------------------------------------------------------------
    def observe(self, session_id: str, ip: str, user_agent: str | None,
                ts: float, path: str | None = None,
                referrer: str | None = None) -> dict:
        """Process one request and return its per-invariant and risk record."""
        b = binding_of(ip, user_agent)
        st = self.sessions.get(session_id)

        if st is None:
            # Session establishment pins the reference binding.
            st = SessionState(pinned=b, last_key=b.key, last_ts=float(ts))
            st.ring.append(b.key)
            self._remember_path(st, path)
            self.sessions[session_id] = st
            zero = {name: 0.0 for name in INVARIANTS}
            return self._record(session_id, st, zero, 0.0, established=True)

        dt = float(ts) - st.last_ts
        if dt < 0.0:
            dt = 0.0

        key = b.key
        changed_binding = key != st.last_key
        is_revisit = changed_binding and key in st.ring
        changed_scope = b.scope16 != st.pinned.scope16 and changed_binding

        p = self.cfg.params
        # Only the enabled invariants are evaluated.  Computing the disabled ones
        # anyway would inflate the measured per-request cost of the deployed
        # detector with work it does not do, so the ablation switch has to reach
        # into the hot path rather than only into the weight vector.
        raw = self._ZERO.copy()
        applicable = self._FALSE.copy()
        on = self._on

        if on["V1_agent_mutation"]:
            raw["V1_agent_mutation"] = v1_agent_mutation(b, st.pinned, p)
            applicable["V1_agent_mutation"] = b.browser != "unknown"
        if on["V2_scope_discontinuity"]:
            raw["V2_scope_discontinuity"] = v2_scope_discontinuity(b, st.pinned, p)
            applicable["V2_scope_discontinuity"] = True
        if on["V3_binding_fork"]:
            raw["V3_binding_fork"] = v3_binding_fork(is_revisit)
            applicable["V3_binding_fork"] = True
        if on["V4_transition_velocity"]:
            raw["V4_transition_velocity"] = v4_transition_velocity(changed_scope, dt, p)
            applicable["V4_transition_velocity"] = True
        if on["V5_rate_discontinuity"]:
            raw["V5_rate_discontinuity"] = v5_rate_discontinuity(
                dt, st.ewma_gap, st.n_seen, p)
            applicable["V5_rate_discontinuity"] = (
                st.n_seen >= p.rate_warmup and bool(st.ewma_gap))
        if on["V6_navigation_break"]:
            raw["V6_navigation_break"] = v6_navigation_break(
                referrer, st.path_set, st.n_seen, self.cfg.site_hosts)
            ref_host, _ = referrer_path(referrer)
            applicable["V6_navigation_break"] = (
                bool(ref_host) and ref_host in self.cfg.site_hosts)

        risk = sum(self._w[k] * raw[k] for k in self._w)
        if self.cfg.evidence == "accumulator":
            st.accumulator = self.cfg.decay * st.accumulator + risk
            evidence = st.accumulator
        else:
            evidence = risk

        # --- bounded state update -----------------------------------------
        if changed_binding:
            if key not in st.ring:
                if len(st.ring) >= self.cfg.ring_size:
                    st.ring.popleft()
                st.ring.append(key)
            st.last_key = key
            # A *monotone* move re-pins the reference: a client that has changed
            # network or device is now legitimately at the new binding, so the
            # transition is charged once rather than for the rest of the session.
            # A *revisit* never re-pins, because when two bindings are
            # interleaved there is no basis for deciding which one is the owner.
            if self.cfg.migrate_reference and not is_revisit:
                st.pinned = b
        st.ewma_gap = dt if st.ewma_gap is None else (
            p.ewma_alpha * dt + (1.0 - p.ewma_alpha) * st.ewma_gap)
        st.last_ts = float(ts)
        st.n_seen += 1
        self._remember_path(st, path)
        if risk > st.peak_risk:
            st.peak_risk = risk
        if evidence > st.evidence_peak:
            st.evidence_peak = evidence
        if st.alerted_at is None and evidence >= self.cfg.threshold:
            st.alerted_at = st.n_seen - 1

        return self._record(session_id, st, raw, risk, established=False,
                            evidence=evidence, applicable=applicable)

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _record(session_id: str, st: SessionState, raw: dict[str, float],
                risk: float, *, established: bool, evidence: float = 0.0,
                applicable: dict[str, bool] | None = None) -> dict:
        rec = {"session_id": session_id, "request_index": st.n_seen - 1,
               "risk": float(evidence), "instant_risk": float(risk),
               "established": established, "peak_risk": float(st.peak_risk)}
        rec.update({name: float(raw[name]) for name in INVARIANTS})
        rec.update({f"A_{name}": bool((applicable or {}).get(name, False))
                    for name in INVARIANTS})
        rec["explanation"] = "|".join(
            f"{name}={raw[name]:.2f}" for name in INVARIANTS if raw[name] > 0.0)
        return rec

    def run(self, requests) -> list[dict]:
        """Process an iterable of request dicts in arrival order."""
        out = []
        for r in requests:
            out.append(self.observe(r["session_id"], r["ip"], r.get("ua"),
                                    r["ts"], r.get("path"), r.get("referrer")))
        return out


# ============================================================================
# Label-free calibration: weights and threshold
# ============================================================================

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
    reference migration and the evidence accumulator --- so that the threshold is
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
