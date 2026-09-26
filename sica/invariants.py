"""Session-continuity invariants.

Each invariant is a deterministic function of (i) the incoming request and
(ii) the bounded state accumulated for the session so far.  Every invariant
returns a bounded violation degree in ``[0, 1]``; ``0`` means "consistent with
an uninterrupted single-client session".

The invariants are chosen so that each one has a distinct security rationale
and so that a benign explanation exists for the low-severity end of its range.
Nothing here is fitted: all constants are physical or protocol-level and are
declared in :class:`InvariantParams`.
"""
from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import Binding

__all__ = ["InvariantParams", "INVARIANTS", "DEFAULT_INVARIANTS", "N_INVARIANTS"]

INVARIANTS: tuple[str, ...] = (
    "V1_agent_mutation",
    "V2_scope_discontinuity",
    "V3_binding_fork",
    "V4_transition_velocity",
    "V5_rate_discontinuity",
    "V6_navigation_break",
)
N_INVARIANTS = len(INVARIANTS)

#: The invariants used by the final detector.
#:
#: Chosen on the development seeds (100-119, disjoint from the reporting seeds)
#: by threshold-free ROC AUC, required to agree across both workloads.  V4, V5
#: and V6 stay implemented only so that the E3 ablation can restore them:
#:
#: * V4 (transition velocity) fires on the same event V2 already reports, and its
#:   300 s settle time exceeds every session in these logs (all are under 60 s).
#: * V5 (rate discontinuity) reads inter-arrival times, which are generator
#:   artefacts in these logs (the minute field is degenerate).
#: * V6 (navigation break) lowered ROC AUC on W1 and cannot fire on W2, which
#:   carries almost no referrers.
#:
#: Dropping V3 raises F1 at the 1% operating point but lowers ROC AUC; V3 is kept
#: because the selection criterion was fixed in advance (see the E3 ablation).
DEFAULT_INVARIANTS: tuple[str, ...] = (
    "V1_agent_mutation",
    "V2_scope_discontinuity",
    "V3_binding_fork",
)


@dataclass(frozen=True)
class InvariantParams:
    """Fixed, declared constants for the invariant set.

    None of these are selected against evaluation labels.  ``version_severity``
    and ``subnet_severity`` encode the *prior* that a browser upgrade or an
    intra-scope address change is a weaker signal than a family substitution or
    an inter-scope move; ``t_settle`` and ``rate_beta`` encode physical and
    behavioural plausibility bounds.
    """

    version_severity: float = 0.35   # browser major-version change only
    host_severity: float = 0.15      # address change inside the same /24
    subnet_severity: float = 0.45    # /24 change inside the same /16
    t_settle: float = 300.0          # s; below this an inter-scope move is implausible
    rate_beta: float = 0.25          # fraction of the session's established gap
    rate_warmup: int = 3             # requests before the rate model is trusted
    ewma_alpha: float = 0.3          # inter-arrival smoothing


# ---------------------------------------------------------------------------
# Individual invariants.  Each takes explicit arguments so that it can be
# unit-tested in isolation and reasoned about without the monitor.
# ---------------------------------------------------------------------------

def v1_agent_mutation(current: Binding, pinned: Binding, p: InvariantParams) -> float:
    """The client software identity changed within one session.

    Rationale: a browser does not change family, operating system or device
    class between two requests of the same session.  A major-version change is
    possible in principle (an upgrade plus a restart) but does not preserve an
    in-memory session in practice, so it is scored as weak rather than zero
    evidence.
    """
    if current.core != pinned.core:
        return 1.0
    if current.version != pinned.version:
        return p.version_severity
    return 0.0


def v2_scope_discontinuity(current: Binding, pinned: Binding, p: InvariantParams) -> float:
    """The network location of the client changed relative to the pinned one.

    Rationale: session identifiers are bearer tokens, so a token presented from
    a different administrative network than the one that obtained it is the
    canonical observable of replay.  Grading over three levels is what separates
    this invariant from address pinning, and it is essential rather than
    cosmetic.  A new address inside the same /24 is the ordinary outcome of a
    DHCP lease renewal or a carrier-NAT pool rotation and is very weak evidence;
    a /24 change means a different access network within the same administrative
    domain; a /16 change means the client has left the network that obtained the
    identifier.  A rule that treats all three alike inherits the rate of the most
    common one as its false-alarm rate.
    """
    if current.scope16 != pinned.scope16:
        return 1.0
    if current.prefix24 != pinned.prefix24:
        return p.subnet_severity
    if current.address != pinned.address:
        return p.host_severity
    return 0.0


def v3_binding_fork(is_revisit: bool) -> float:
    """Two distinct bindings are *interleaved* inside one session.

    Rationale: this is the discriminative invariant.  A user who legitimately
    roams produces a *monotone* sequence of bindings (``A A A B B B``): the old
    binding is abandoned.  A live hijack, in which attacker and victim use the
    same identifier concurrently, necessarily produces a *revisit*
    (``A A B A B``), because the victim keeps browsing.  A revisit therefore
    has no benign explanation under a single-client session, whereas a single
    forward transition has several.
    """
    return 1.0 if is_revisit else 0.0


def v4_transition_velocity(changed_scope: bool, dt: float, p: InvariantParams) -> float:
    """A network-scope transition happened faster than it physically could settle.

    Rationale: leaving one administrative network and issuing an authenticated
    request from another requires association, addressing and routing to
    converge.  Two consecutive requests from different /16 scopes separated by
    a fraction of a second indicate two concurrent clients rather than one
    moving client.  Where geographic coordinates are available the same
    invariant is evaluated as an implied ground speed.
    """
    if not changed_scope:
        return 0.0
    if dt <= 0.0:
        return 1.0
    return max(0.0, min(1.0, 1.0 - dt / p.t_settle))


def v5_rate_discontinuity(dt: float, ewma_gap: float | None, n_seen: int,
                          p: InvariantParams) -> float:
    """The request cadence broke sharply from the session's established rhythm.

    Rationale: an attacker replaying a token is typically scripted and issues
    requests far faster than the interactive client that created the session.
    The reference is the session's *own* smoothed inter-arrival gap, so no
    population-level rate assumption is needed.
    """
    if ewma_gap is None or n_seen < p.rate_warmup or ewma_gap <= 0.0:
        return 0.0
    reference = p.rate_beta * ewma_gap
    if dt >= reference:
        return 0.0
    return max(0.0, min(1.0, 1.0 - dt / reference))


def referrer_path(referrer: str | None) -> tuple[str, str]:
    """Split a Referer header into ``(host, path)``; empty strings when absent.

    An off-site or absent referrer is normal at any point in a session (a user
    may follow an external link into a page), so the host is retained in order
    to restrict the invariant to *claimed in-site* navigation.
    """
    if referrer is None:
        return ("", "")
    text = str(referrer).strip()
    if text in {"", "-", "nan"}:
        return ("", "")
    body = text.split("://", 1)[1] if "://" in text else text
    host, _, rest = body.partition("/")
    return (host, "/" + rest.split("?", 1)[0].split("#", 1)[0] if rest else "/")


def v6_navigation_break(referrer: str | None, seen_paths: frozenset[str] | set[str],
                        n_seen: int, site_hosts: frozenset[str] | set[str]) -> float:
    """A request claims in-site navigation from a page this session never visited.

    Rationale: a client that is browsing carries a referrer chain whose in-site
    links point at pages it has already retrieved.  A replayed identifier aimed
    at a target endpoint carries either no chain or a fabricated one.  Only
    *in-site* referrers are judged: an absent or off-site referrer has an
    ordinary benign explanation at any point in a session and scores zero, so
    the invariant is silent on workloads that carry no referrers at all rather
    than producing noise on them.
    """
    if n_seen < 1:
        return 0.0
    host, path = referrer_path(referrer)
    if not host or host not in site_hosts:
        return 0.0
    return 0.0 if path in seen_paths else 1.0
