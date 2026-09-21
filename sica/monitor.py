"""Stateful per-session continuity monitor.

The monitor keeps a fixed-size record per live session and performs a constant
amount of work per request.  It emits, for every request, the vector of
invariant violation degrees, the aggregated risk, and the decision under the
frozen operating threshold.

Complexity
----------
Time  : O(1) per request (bounded ring of size ``ring_size``, bounded path
        window of size ``path_window``; no scan over session history).
Memory: O(1) per live session; O(S) for S concurrently live sessions.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .fingerprint import Binding, binding_of
from .invariants import (
    DEFAULT_INVARIANTS,
    INVARIANTS,
    referrer_path,
    InvariantParams,
    v1_agent_mutation,
    v2_scope_discontinuity,
    v3_binding_fork,
    v4_transition_velocity,
    v5_rate_discontinuity,
    v6_navigation_break,
)

__all__ = ["SessionState", "MonitorConfig", "ContinuityMonitor", "EQUAL_WEIGHTS"]

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
