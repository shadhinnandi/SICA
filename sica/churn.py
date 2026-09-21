"""Benign binding churn: legitimate mobility injected into the negative class.

Sessionising real access logs by ``(address, User-Agent)`` yields ground truth
for "these requests came from one client", but it also makes benign binding
changes *impossible by construction*: within such a session the address and the
agent are constant.  Evaluating a continuity detector on that negative class
would be vacuous --- every binding change would be an attack, and the reported
false-alarm rate of the binding invariants would be zero for a reason that has
nothing to do with the detector.

This module therefore restores the phenomenon that makes the problem hard.  A
declared share of benign sessions receives a *legitimate* binding change:

``M1_handover``     the client's address changes mid-session, either inside the
                    same /16 (access-point or DHCP change) or to a different
                    /16 (Wi-Fi to cellular).  **Monotone**: the old address is
                    never used again.
``M2_agent_update`` the browser's major version increments mid-session and the
                    session is resumed.  **Monotone**.
``M3_combined``     both of the above at the same point.  **Monotone**.
``M4_flapping``     the client alternates between two interfaces (dual-homed
                    host, or IPv4/IPv6 selection instability).  **Interleaved**
                    --- this is the one benign phenomenon that mimics a live
                    hijack, and it is included deliberately so that the cost of
                    the forking invariant is measured rather than assumed.

The true rates of these phenomena in a given deployment are unknown, so they are
declared parameters and are swept in the robustness experiment rather than
fitted.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass

import numpy as np

from .fingerprint import VERSION_KEYS, parse_user_agent
from .sessionize import Session

__all__ = ["ChurnConfig", "CHURN_KINDS", "apply_churn", "bump_agent_version",
           "build_agent_pool", "agent_update"]

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
