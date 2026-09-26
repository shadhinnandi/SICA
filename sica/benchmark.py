"""Benchmark construction: benign mobility and simulated session hijacking.

The logs contain no labelled hijacks, so the evaluation builds them on top of
real traffic.  Two things are added to the evaluation data:

* **Benign churn** (``apply_churn``).  A declared share of benign sessions gets a
  legitimate binding change: an address move (M1), a browser version update
  (M2), both (M3), or interface flapping between two addresses (M4, the one
  benign pattern that interleaves like a hijack).
* **Hijacks** (``inject_session``).  An attacker takes over a session at a
  theft point drawn from 25-50% of its length.  Attacker requests are real
  requests from a different client of the same server, with only the binding
  replaced.  Sessions keep their original length.

Masquerade levels (what the attacker reproduces from the victim's binding):

    L0  own address (different /16),        own agent
    L1  own address (different /16),        victim's agent
    L2  address in victim's /16, new /24,   own agent
    L3  address in victim's /24,            victim's agent
    L4  victim's own address (shared NAT),  victim's agent   (undetectable)
    L5  victim's own address (shared NAT),  own agent

Modes: ``takeover`` (victim stops at the theft point) and ``concurrent``
(victim keeps browsing, so bindings interleave).
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass

import numpy as np

from .fingerprint import VERSION_KEYS, parse_user_agent
from .sessionize import Request, Session

__all__ = ["InjectionConfig", "LEVELS", "LEVELS_ADDRESS_VISIBLE", "LEVELS_COLOCATED",
           "LEVELS_ALL", "MODES", "build_donor_pool", "inject_session", "inject_corpus",
           "ChurnConfig", "CHURN_KINDS", "apply_churn", "bump_agent_version",
           "build_agent_pool", "agent_update"]


# ============================================================================
# Hijack injection (masquerade levels L0-L5, two modes)
# ============================================================================

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


# ============================================================================
# Benign binding churn (legitimate mobility)
# ============================================================================

CHURN_KINDS = ("M1_handover", "M2_agent_update", "M3_combined", "M4_flapping")
_DIGITS = re.compile(r"\d+")


@dataclass(frozen=True)
class ChurnConfig:
    """Declared rates of benign binding churn in the negative class."""

    monotone_rate: float = 0.15      # share of benign sessions with M1/M2/M3
    flapping_rate: float = 0.05      # share of benign sessions with M4
    # Granularity mix of benign address changes.  A DHCP lease renewal or a
    # carrier-NAT pool rotation inside the same /24 is the common case; leaving
    # the /16 entirely (wireless to cellular) is the rare one.  Omitting the
    # intra-/24 case would make address pinning appear far more deployable than
    # it is, because the change that dominates real traffic would never occur.
    host_share: float = 0.50         # new address, same /24
    subnet_share: float = 0.30       # new /24, same /16
    cross_scope_share: float = 0.20  # new /16
    min_requests: int = 4


GRANULARITIES = ("host", "subnet", "scope")


def _granularity(cfg: ChurnConfig, rng: np.random.Generator) -> str:
    shares = np.array([cfg.host_share, cfg.subnet_share, cfg.cross_scope_share],
                      dtype=float)
    total = shares.sum()
    if total <= 0:
        return "host"
    return GRANULARITIES[int(rng.choice(3, p=shares / total))]


def _shift_ip(ip: str, rng: np.random.Generator, granularity: str) -> str:
    """Move an address at one of three granularities: host, subnet or scope."""
    parts = ip.split(".")
    if len(parts) != 4:
        return ip
    a, b, c, d = parts
    if granularity == "scope":
        nb = int(rng.integers(0, 256))
        while str(nb) == b:
            nb = int(rng.integers(0, 256))
        return f"{a}.{nb}.{int(rng.integers(0, 256))}.{int(rng.integers(1, 255))}"
    if granularity == "subnet":
        nc = int(rng.integers(0, 256))
        while str(nc) == c:
            nc = int(rng.integers(0, 256))
        return f"{a}.{b}.{nc}.{int(rng.integers(1, 255))}"
    nd = int(rng.integers(1, 255))
    while str(nd) == d:
        nd = int(rng.integers(1, 255))
    return f"{a}.{b}.{c}.{nd}"


def bump_agent_version(ua: str) -> str | None:
    """Increment the major version the *fingerprinter* reads, or ``None`` if there is none.

    The version is located with :data:`sica.fingerprint.VERSION_KEYS`, the same table the
    fingerprint reads, so an update is observable by construction for every client family
    that advertises a version at all.  The previous implementation matched a hard-coded list
    of browser tokens and appended ``" Build/2"`` to anything else; on a workload of
    package-manager clients that suffix changed the raw string while leaving every parsed
    field identical, so the benign agent-update class existed in name only and V1's benign
    firing rate there was measured as exactly zero.

    Returning ``None`` rather than a cosmetic edit is deliberate: a session whose agent
    carries no version cannot undergo an observable version upgrade, and the caller records
    that instead of pretending otherwise.
    """
    browser, version, _os_family, _device = parse_user_agent(ua)
    if not version:
        return None
    low = ua.lower()
    for key in VERSION_KEYS.get(browser, ()):
        idx = low.find(key)
        if idx < 0:
            continue
        m = _DIGITS.search(ua, idx + len(key), idx + len(key) + 12)
        if m:
            return ua[:m.start()] + str(int(m.group()) + 1) + ua[m.end():]
    return None


def build_agent_pool(sessions: list[Session]) -> dict[tuple, dict[str, str]]:
    """Index the *real* agent strings in a corpus by agent core and major version.

    A benign agent update is drawn from this pool where possible, so the churned session
    carries a User-Agent string that a real client of this very server actually sent, rather
    than a synthesised one.
    """
    pool: dict[tuple, dict[str, str]] = {}
    for s in sessions:
        for r in s.requests:
            browser, version, os_family, device = parse_user_agent(r.ua)
            if not version:
                continue
            pool.setdefault((browser, os_family, device), {}).setdefault(version, r.ua)
    return pool


def agent_update(ua: str, pool: dict[tuple, dict[str, str]],
                 rng: np.random.Generator) -> str | None:
    """A mid-session client-software upgrade: same client, different major version.

    Preference is given to a real agent string observed elsewhere in the same corpus with
    the same agent core and a different major version --- the most realistic available
    representation of "this client updated". Only when the corpus offers no such string does
    the version get incremented synthetically.
    """
    browser, version, os_family, device = parse_user_agent(ua)
    observed = pool.get((browser, os_family, device), {})
    candidates = sorted(u for v, u in observed.items() if v != version)
    if candidates:
        return candidates[int(rng.integers(len(candidates)))]
    return bump_agent_version(ua)


def apply_churn(sessions: list[Session], cfg: ChurnConfig,
                rng: np.random.Generator) -> tuple[list[Session], dict]:
    """Apply benign churn to a share of the benign sessions in ``sessions``.

    Attack sessions are left untouched: churn models the legitimate client, and
    injecting it into an already-hijacked session would confound the label.
    """
    out: list[Session] = []
    counts = {k: 0 for k in CHURN_KINDS}
    skipped_agent_update = 0
    pool = build_agent_pool(sessions)
    for s in sessions:
        if s.label == 1 or s.n < cfg.min_requests:
            out.append(s)
            continue
        u = float(rng.random())
        if u < cfg.flapping_rate:
            kind = "M4_flapping"
        elif u < cfg.flapping_rate + cfg.monotone_rate:
            kind = CHURN_KINDS[int(rng.integers(0, 3))]
        else:
            out.append(s)
            continue

        reqs = [copy.copy(r) for r in s.requests]
        # The change point leaves at least one request on each side, so that a
        # churned session genuinely contains a transition.
        cut = int(rng.integers(1, len(reqs))) if kind != "M4_flapping" \
            else int(rng.integers(1, max(2, len(reqs) - 1)))
        granularity = _granularity(cfg, rng)
        new_ip = _shift_ip(reqs[0].ip, rng, granularity)
        new_ua = agent_update(reqs[0].ua, pool, rng)
        if new_ua is None and kind in ("M2_agent_update", "M3_combined"):
            # This client advertises no version, so it cannot undergo an observable upgrade.
            # Recording the skip keeps the realised churn mix honest rather than labelling a
            # session as agent-churned when nothing about its agent changed.
            skipped_agent_update += 1
            if kind == "M2_agent_update":
                out.append(s)
                continue
            kind = "M1_handover"

        if kind == "M1_handover":
            for r in reqs[cut:]:
                r.ip = new_ip
        elif kind == "M2_agent_update":
            for r in reqs[cut:]:
                r.ua = new_ua
        elif kind == "M3_combined":
            for r in reqs[cut:]:
                r.ip, r.ua = new_ip, new_ua
        else:  # M4_flapping: alternate between the two addresses
            for i, r in enumerate(reqs):
                if i >= cut and (i - cut) % 2 == 1:
                    r.ip = new_ip

        counts[kind] += 1
        # The granularity is recorded in the scenario name so that false alarms
        # can be attributed to the specific kind of legitimate mobility that
        # produced them.
        suffix = "" if kind == "M2_agent_update" else f":{granularity}"
        churned = Session(session_id=s.session_id, client=s.client, requests=reqs,
                          label=0, scenario=f"{kind}{suffix}")
        out.append(churned)

    stats = {"churn_counts": counts,
             "churned_sessions": int(sum(counts.values())),
             "skipped_agent_update": int(skipped_agent_update),
             "monotone_rate": cfg.monotone_rate,
             "flapping_rate": cfg.flapping_rate,
             "host_share": cfg.host_share, "subnet_share": cfg.subnet_share,
             "cross_scope_share": cfg.cross_scope_share}
    return out, stats
