"""Controlled session-hijack injection into real background traffic.

No public corpus labels individual HTTP requests as belonging to a hijacked
session, so the attack condition is constructed rather than observed.  The
construction is designed to suppress the failure mode that invalidates naive
semi-synthetic benchmarks: *the attacker's requests are real requests issued by
a different real client in the same log*, so their marginal distributions
(paths, sizes, status codes, inter-arrival times, agents, addresses) are drawn
from exactly the same population as the benign traffic, and length matching
removes the request-count artefact.

What this does and does not buy, stated against the measurement rather than
asserted.  It removes the gross artefacts: request count, session duration, byte
volume and inter-arrival statistics all sit at chance (marginal ROC AUC 0.49--0.52
on both workloads; ``results/tables/e5_marginal_audit.csv``).  It does **not**
make the classes marginally inseparable in general.  On the package-manager
workload the number of distinct paths in a session reaches marginal ROC AUC
**0.732**, and an ML-free Mahalanobis detector over content features reaches
**0.731**, because a donor package-manager client fetches a different set of
package paths than the victim does.  An earlier version of this docstring claimed
that "no classifier of per-request features can separate the classes"; that claim
is false and is contradicted by this project's own leakage audit.

The defensible statement is narrower and is what the design actually relies on:
the retained invariants read no path, timing, volume or byte-count feature --- a
structural property checked mechanically in ``pipeline/exp05_leakage.py`` --- so
the residual content shortcut cannot reach the detector, and the detector's
ranking quality (~0.96) is far above what that shortcut yields (~0.73).

Two orthogonal factors are varied.

Masquerade level --- how much of the victim's binding the attacker reproduces:

======  ======================================  ===========================
Level   Attacker network address                Attacker User-Agent
======  ======================================  ===========================
``L0``  donor's own address (different /16)     donor's own agent
``L1``  donor's own address (different /16)     victim's agent (cloned)
``L2``  synthetic address in victim's /16,      donor's own agent
        different /24
``L3``  synthetic address in victim's /24       victim's agent (cloned)
``L4``  the victim's own address (shared NAT     victim's agent (cloned)
        or proxy)
``L5``  the victim's own address (shared NAT     donor's own agent
        or proxy)
======  ======================================  ===========================

Address change is not the definition of hijacking, and the level set exists to keep
the two apart.  ``L0``--``L3`` are the *address-visible* levels: the attacker's
address differs from the victim's, so a rule that alerts on any address change
detects all of them **by construction**.  Evaluating on those alone would make
address pinning perfect by definition and would reduce the benchmark to measuring
address-change detection.

``L4`` and ``L5`` are the *co-located* levels: the attacker is behind the same
network address translator or forward proxy as the victim and presents an
identical address, so no address-based rule can see the attack at all.  They
differ in what else the attacker reproduces.  ``L4`` also clones the agent, and is
therefore invisible to *every* binding-based server-side signal --- it is the
acknowledged blind spot of this entire approach and is reported as such, not
quietly excluded.  ``L5`` is the co-located attacker on a different device or
client program, which carries no address signal whatsoever but does break agent
continuity; it is the case that demonstrates most directly that hijack detection
and address-change detection are different problems.

All six levels form the reported envelope.  The complementary direction --- benign
sessions that *do* change address --- is supplied by the churn model in
``sica.churn``, so neither the presence nor the absence of an address change is
sufficient to determine the label.


Concurrency --- whether the victim keeps using the session:

``takeover``    the victim stops after the theft; only attacker requests follow.
``concurrent``  victim and attacker interleave, which is what a live cookie
                replay against an active user produces.

``L3`` combined with ``takeover`` is deliberately included even though it is
unobservable to any server-side continuity signal: reporting it is what makes
the evaluated envelope honest.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass

import numpy as np

from .sessionize import Request, Session

__all__ = ["InjectionConfig", "LEVELS", "LEVELS_ADDRESS_VISIBLE", "LEVELS_COLOCATED",
           "LEVELS_ALL", "MODES", "build_donor_pool", "inject_session", "inject_corpus"]

#: Levels in which the attacker's address differs from the victim's.  Any rule that
#: alerts on an address change detects every one of them by construction.
LEVELS_ADDRESS_VISIBLE = ("L0", "L1", "L2", "L3")
#: Levels in which the attacker presents the victim's own address (shared NAT or proxy),
#: so no address-based rule can see the attack.
LEVELS_COLOCATED = ("L4", "L5")
#: The reported envelope.
LEVELS_ALL = LEVELS_ADDRESS_VISIBLE + LEVELS_COLOCATED
#: Backwards-compatible alias for the address-visible subset.
LEVELS = LEVELS_ADDRESS_VISIBLE
MODES = ("takeover", "concurrent")


@dataclass(frozen=True)
class InjectionConfig:
    """Parameters of the attack construction."""

    level: str = "L0"
    mode: str = "concurrent"
    attack_fraction: float = 0.4      # attacker requests as a fraction of victim length
    min_attacker_requests: int = 3
    #: Upper bound on the attacker's share.  It applies to ``concurrent`` only, where the
    #: share is a free parameter.  In a ``takeover`` the attacker replaces the whole
    #: remaining tail, so the share is *determined* by the theft point; capping it there
    #: would mean either the theft point or the cap has to give, and the theft point is the
    #: experimental condition.  See :func:`inject_session`.
    max_attacker_requests: int = 40
    earliest_takeover: float = 0.25   # theft point as a fraction of the session
    latest_takeover: float = 0.50
    theft_delay_s: float | None = None  # None: drawn from U(0.5, 5.0) seconds


def build_donor_pool(sessions: list[Session], min_len: int = 3) -> list[Session]:
    """Sessions usable as sources of attacker request content."""
    return [s for s in sessions if s.n >= min_len]


def _synthetic_ip(victim_ip: str, rng: np.random.Generator, same24: bool) -> str:
    parts = victim_ip.split(".")
    if len(parts) != 4:
        return victim_ip
    a, b, c, d = parts
    if same24:
        host = int(rng.integers(1, 255))
        while str(host) == d:
            host = int(rng.integers(1, 255))
        return f"{a}.{b}.{c}.{host}"
    third = int(rng.integers(0, 256))
    while str(third) == c:
        third = int(rng.integers(0, 256))
    return f"{a}.{b}.{third}.{int(rng.integers(1, 255))}"


def _scope16(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else ip


def inject_session(victim: Session, donors: list[Session], cfg: InjectionConfig,
                   rng: np.random.Generator,
                   reasons: dict[str, int] | None = None) -> Session | None:
    """Return a copy of ``victim`` containing injected attacker requests.

    ``None`` is returned when the requested condition cannot be realised for this victim, so
    that the caller can leave the session benign rather than weaken the construction.  When
    ``reasons`` is supplied it is incremented with why, so that the *effective* experimental
    condition is reported rather than assumed.

    The theft point is treated as the experimental condition throughout: it is drawn from
    ``[earliest_takeover, latest_takeover]`` and is never moved afterwards.  A session whose
    requested theft point cannot be supplied with real attacker content is refused and
    counted, which is visible, rather than relocated, which is not.
    """
    def refuse(why: str) -> None:
        if reasons is not None:
            reasons[why] = reasons.get(why, 0) + 1
        return None

    n = victim.n
    lo = max(2, int(np.ceil(cfg.earliest_takeover * n)))
    hi = max(lo, int(np.floor(cfg.latest_takeover * n)))
    if hi >= n:
        hi = n - 1
    if lo > hi:
        return refuse("session_too_short_for_theft_window")
    cut = int(rng.integers(lo, hi + 1))

    # How much real attacker content this theft point requires.  In a takeover the victim
    # falls silent, so the attacker must supply the entire remaining tail; the donor has to
    # be long enough to do that, or the requested condition cannot be honoured at all.
    required = n - cut - 1 if cfg.mode == "takeover" else cfg.min_attacker_requests
    if cfg.mode == "takeover" and required < cfg.min_attacker_requests:
        return refuse("theft_window_leaves_too_little_tail")

    # Every network scope the victim presents anywhere in the session.  Benign churn may move
    # the victim between scopes, so an off-network donor must be off *every* scope the victim
    # uses rather than merely off the one it started from.
    victim_scopes = {_scope16(r.ip) for r in victim.requests}
    victim_agents = {r.ua for r in victim.requests}
    # Admissible donors: a different client, and for L0/L1 also a different
    # network scope, so that the attacker is genuinely off-network.
    order = rng.permutation(len(donors))
    donor = None
    for idx in order:
        cand = donors[int(idx)]
        if cand.client == victim.client or cand.n < required:
            continue
        if cfg.level in ("L0", "L1") and _scope16(cand.client[0]) in victim_scopes:
            continue
        if cfg.level == "L5" and cand.client[1] in victim_agents:
            # L5 is the co-located attacker on a *different* client program.  Without this
            # constraint a donor that happens to advertise the victim's agent -- the common
            # case on a workload dominated by one agent -- would silently reduce L5 to L4.
            continue
        donor = cand
        break
    if donor is None:
        return refuse("no_admissible_donor")

    # How many attacker requests, and where the theft actually lands.
    #
    # Length matching is a hard requirement: an injected session must contain
    # exactly as many requests as the original, or request count alone predicts
    # the label and every detector inherits that artefact.  The attacker's
    # requests therefore *replace* an equal number of the victim's.
    #
    # The two modes reach that differently, and the difference is the definition
    # of the modes rather than an implementation detail.  In a takeover the
    # victim falls silent at the theft point, so the attacker replaces the whole
    # remaining tail and the attacker's share is fixed by the theft position.
    # In a concurrent hijack the victim keeps browsing, so the attacker's share
    # is free and ``attack_fraction`` sets it, with an equal number of the
    # victim's post-theft requests displaced to keep the count.
    #
    # ``max_attacker_requests`` therefore bounds the *concurrent* share only.  Applying it to
    # a takeover would contradict the mode: the share there is not free, and the previous
    # implementation resolved the contradiction by re-deriving ``cut`` from the cap, which
    # silently relocated a requested theft at 20-30% of the session to 60%.  The theft point
    # is the experimental condition, so the cap gives way and an unsatisfiable request is
    # refused and counted instead.
    if cfg.mode == "takeover":
        k = n - cut - 1              # the whole remaining tail; ``cut`` is never moved
        if k > donor.n:
            return refuse("donor_too_short_for_takeover_tail")
    elif cfg.mode == "concurrent":
        # At least one victim request must survive *after* the theft point, or
        # displacing the tail turns the scenario into a takeover wearing a
        # concurrent label.  The final request of the session is therefore never
        # displaced, which bounds the attacker's share at n - cut - 2.
        k = int(np.clip(round(cfg.attack_fraction * n),
                        cfg.min_attacker_requests, cfg.max_attacker_requests))
        k = min(k, n - cut - 2, donor.n)
        if k < cfg.min_attacker_requests:
            return refuse("theft_window_leaves_too_little_tail")
    else:
        raise ValueError(f"unknown mode: {cfg.mode}")

    start = int(rng.integers(0, donor.n - k + 1))
    donor_run = donor.requests[start:start + k]

    # Attacker binding under the masquerade level.
    #
    # The reference is the binding the victim *actually presents at the theft point*, not
    # the one its session started from.  Benign churn is applied before injection, so a
    # victim may have legitimately moved network or updated its agent before the theft; a
    # level derived from ``Session.client`` would then place the attacker further from the
    # victim than the level declares, making the harder cells artificially detectable.
    ref = victim.requests[cut]
    ref_ip, ref_ua = ref.ip, ref.ua
    if cfg.level == "L0":
        atk_ip, atk_ua = donor.client[0], donor.client[1]
    elif cfg.level == "L1":
        atk_ip, atk_ua = donor.client[0], ref_ua
    elif cfg.level == "L2":
        atk_ip, atk_ua = _synthetic_ip(ref_ip, rng, same24=False), donor.client[1]
    elif cfg.level == "L3":
        atk_ip, atk_ua = _synthetic_ip(ref_ip, rng, same24=True), ref_ua
    elif cfg.level == "L4":
        atk_ip, atk_ua = ref_ip, ref_ua
    elif cfg.level == "L5":
        # Co-located but a different client program: no address signal at all, so only a
        # non-address continuity signal can see it.
        atk_ip, atk_ua = ref_ip, donor.client[1]
    else:
        raise ValueError(f"unknown masquerade level: {cfg.level}")

    # Attacker cadence: the donor's own real inter-arrival gaps, anchored just
    # after the theft point.  Gaps are preserved so that the attacker's timing
    # is a real client's timing rather than an artificial burst.
    gaps = [max(0.0, donor_run[i].ts - donor_run[i - 1].ts) for i in range(1, len(donor_run))]
    delay = (float(cfg.theft_delay_s) if cfg.theft_delay_s is not None
             else float(rng.uniform(0.5, 5.0)))
    t0 = victim.requests[cut].ts + delay

    if cfg.mode == "concurrent":
        # A concurrent hijack is defined by the victim and the attacker using the
        # identifier at the same time, so the construction has to realise that
        # rather than hope for it.  With the donor's raw gaps the attacker's
        # activity frequently ran past the victim's last request, which produced
        # a session labelled "concurrent" that contained no interleaving at all.
        # The donor's gap *pattern* is therefore kept but compressed, where
        # necessary, to fit inside the victim's remaining window.  Only
        # compression is applied: stretching would slow the attacker artificially.
        # This alters inter-arrival magnitudes, which is admissible here because
        # no retained invariant reads a timestamp difference.
        # The *delay* has to be bounded by the window too, not only the gap span.  A delay
        # larger than the victim's remaining window places the attacker's first request
        # after the victim's last one, so every surviving victim request precedes the
        # attacker and the session is a takeover carrying a concurrent label.  That is not
        # hypothetical: the sessions in these corpora span at most 59 seconds, while E4
        # sweeps this parameter to 60 and 600 seconds, at which only 34% of "concurrent"
        # sessions still interleaved.  Clamping keeps the swept parameter varying what it
        # claims to vary -- how late inside the session the theft begins -- instead of
        # silently varying the scenario type.
        window = victim.requests[-1].ts - victim.requests[cut].ts
        span = sum(gaps)
        if window > 0.0:
            delay = min(delay, 0.05 * window)
            t0 = victim.requests[cut].ts + delay
            if span > 0.9 * window:
                scale = 0.9 * window / span
                gaps = [g * scale for g in gaps]

    times, t = [t0], t0
    for g in gaps:
        t += g
        times.append(t)

    attacker = [
        Request(ip=atk_ip, ua=atk_ua, ts=float(times[i]), path=donor_run[i].path,
                referrer=donor_run[i].referrer, status=donor_run[i].status,
                nbytes=donor_run[i].nbytes, injected=1)
        for i in range(len(donor_run))
    ]

    benign = [copy.copy(r) for r in victim.requests]
    if cfg.mode == "takeover":
        # The victim falls silent at the theft point and issues nothing further.
        kept = benign[: cut + 1]
    else:
        # The victim keeps browsing; k of its post-theft requests are displaced.
        # The final request is excluded from the candidates so that the session
        # always ends with victim traffic and the interleaving is real.
        tail = list(range(cut + 1, n - 1))
        drop = set(rng.choice(tail, size=k, replace=False).tolist())
        kept = [r for i, r in enumerate(benign) if i not in drop]

    merged = sorted(kept + attacker, key=lambda r: r.ts)
    if not any(r.injected for r in merged):
        return refuse("no_attacker_request_survived")

    out = Session(session_id=victim.session_id, client=victim.client,
                  requests=merged, label=1,
                  scenario=f"{cfg.level}_{cfg.mode}")
    out.first_injected_index = next(i for i, r in enumerate(merged) if r.injected)
    return out


def inject_corpus(sessions: list[Session], donors: list[Session],
                  attack_rate: float, cfg: InjectionConfig,
                  rng: np.random.Generator) -> tuple[list[Session], dict]:
    """Inject into a random ``attack_rate`` share of eligible sessions.

    Sessions that are too short to admit a takeover point, or for which no
    admissible donor exists, remain benign; the returned statistics record how
    often that happened so that the realised attack prevalence is reported
    rather than assumed.
    """
    out: list[Session] = []
    attempted = injected = 0
    reasons: dict[str, int] = {}
    target = rng.random(len(sessions)) < attack_rate
    for i, s in enumerate(sessions):
        if not target[i]:
            out.append(s)
            continue
        attempted += 1
        made = inject_session(s, donors, cfg, rng, reasons=reasons)
        if made is None:
            out.append(s)
        else:
            out.append(made)
            injected += 1
    stats = {"n_sessions": len(out), "targeted": attempted, "injected": injected,
             "attack_prevalence": injected / max(1, len(out)),
             "level": cfg.level, "mode": cfg.mode,
             "attack_fraction": cfg.attack_fraction,
             "theft_window": [cfg.earliest_takeover, cfg.latest_takeover],
             "refusal_reasons": reasons}
    return out, stats
