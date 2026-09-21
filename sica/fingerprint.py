"""Deterministic client-binding fingerprints derived from a single HTTP request.

A *binding* is the tuple of observable client-side characteristics that a
server can attribute to the client that presented a session identifier.  All
functions here are pure, allocation-light and independent of any model: they
map one request record to a small hashable descriptor.

Design constraints
------------------
* No learned components.  Every mapping is a fixed, auditable rule.
* Bounded work per request: a fixed number of substring tests.
* Version-insensitive *core* identity is separated from the version-sensitive
  full fingerprint so that a benign browser upgrade can be graded differently
  from a device or browser-family substitution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "Binding",
    "VERSION_KEYS",
    "ip_prefix24",
    "ip_scope16",
    "parse_user_agent",
    "binding_of",
]

# ---------------------------------------------------------------------------
# Network scope
# ---------------------------------------------------------------------------

def ip_prefix24(ip: str) -> str:
    """Return the /24 network prefix of an IPv4 address (or /48-like head for v6).

    The /24 is the finest aggregation that survives ordinary DHCP lease churn
    inside one access network, so it is used as the *routing-locality* key.
    """
    if ":" in ip:                       # IPv6: first three hextets ~ /48
        return ":".join(ip.split(":")[:3])
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def ip_scope16(ip: str) -> str:
    """Return the /16 network scope of an IPv4 address (or /32-like head for v6).

    The /16 is used as an autonomous-system *proxy*.  It is deliberately coarse:
    a change of /16 during a live session almost always means the client left
    the administrative network it started in, whereas /24 changes are routine
    for mobile and carrier-NAT clients.
    """
    if ":" in ip:
        return ":".join(ip.split(":")[:2])
    parts = ip.split(".")
    return ".".join(parts[:2]) if len(parts) == 4 else ip


# ---------------------------------------------------------------------------
# User-agent fingerprint
# ---------------------------------------------------------------------------

_VERSION = re.compile(r"(\d+)")

# Ordered because several agents advertise more than one token (e.g. Edge
# advertises Chrome and Safari).  The first match wins.
_BROWSERS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("Edge",      ("edg/", "edge/"),           ()),
    ("Opera",     ("opr/", "opera"),           ()),
    ("Chrome",    ("chrome/", "crios/"),       ("edg/", "opr/")),
    ("Firefox",   ("firefox/", "fxios/"),      ()),
    ("Safari",    ("safari/",),                ("chrome/", "crios/", "edg/", "opr/")),
    ("MSIE",      ("msie", "trident/"),        ()),
    ("AptHTTP",   ("debian apt-http", "apt-http"), ()),
    ("Wget",      ("wget/",),                  ()),
    ("Curl",      ("curl/",),                  ()),
    ("FeedReader", ("feedparser", "feedburner", "feedly", "rss"), ()),
    ("Bot",       ("bot", "spider", "crawler", "slurp", "bingpreview"), ()),
    ("Library",   ("python-", "java/", "libwww", "go-http", "okhttp", "urllib"), ()),
)

_OS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("iOS",      ("iphone", "ipad", "ipod", "cpu os")),
    ("Android",  ("android",)),
    ("Windows",  ("windows nt", "windows")),
    ("macOS",    ("macintosh", "mac os x")),
    ("ChromeOS", ("cros",)),
    ("Ubuntu",   ("ubuntu",)),
    ("Debian",   ("debian",)),
    ("Linux",    ("linux", "x11")),
)


def _browser(ua_low: str) -> str:
    for name, tokens, blockers in _BROWSERS:
        if any(t in ua_low for t in tokens) and not any(b in ua_low for b in blockers):
            return name
    return "Other"


def _os(ua_low: str) -> str:
    for name, tokens in _OS:
        if any(t in ua_low for t in tokens):
            return name
    return "Other"


def _device_class(ua_low: str, os_family: str) -> str:
    if os_family in ("iOS", "Android"):
        return "Mobile" if ("mobile" in ua_low or "iphone" in ua_low) else "Tablet"
    if os_family in ("Windows", "macOS", "ChromeOS", "Ubuntu", "Debian", "Linux"):
        return "Desktop"
    return "Other"


#: Where each client family advertises its own version, in order of preference.  This is the
#: single source of truth: the fingerprint reads a version with it and the benign-churn model
#: writes one with it, so the two cannot drift apart.  ``AptHTTP`` is the case that made the
#: distinction matter: ``Debian APT-HTTP/1.3 (0.9.7.9)`` advertises the *protocol* version
#: after ``apt-http/``, which is 1.3 for every apt client ever observed in these corpora, and
#: the *client package* version in parentheses, which is what actually varies between
#: clients and across an upgrade.  The parenthesised token is the client's own version and is
#: therefore read first.
VERSION_KEYS: dict[str, tuple[str, ...]] = {
    "Chrome": ("chrome/", "crios/"), "Firefox": ("firefox/", "fxios/"),
    "Safari": ("version/", "safari/"), "Edge": ("edg/", "edge/"),
    "Opera": ("opr/", "opera/"), "MSIE": ("msie ", "rv:"),
    "AptHTTP": ("(", "apt-http/"), "Wget": ("wget/",), "Curl": ("curl/",),
}


def _major_version(ua: str, ua_low: str, browser: str) -> str:
    """Major version of the identified client, or '' when not advertised."""
    keys = VERSION_KEYS.get(browser, ())
    for key in keys:
        idx = ua_low.find(key)
        if idx >= 0:
            m = _VERSION.search(ua[idx + len(key): idx + len(key) + 12])
            if m:
                return m.group(1)
    return ""


def parse_user_agent(ua: str | None) -> tuple[str, str, str, str]:
    """Map a User-Agent string to ``(browser, major_version, os_family, device)``.

    Unknown or absent agents collapse to a single explicit ``unknown`` identity
    rather than to a missing value, so that an agent disappearing mid-session is
    itself a detectable change rather than a silently ignored one.
    """
    if ua is None or not str(ua).strip() or str(ua).strip() in {"-", "nan", "unknown"}:
        return ("unknown", "", "unknown", "unknown")
    text = str(ua)
    low = text.lower()
    browser = _browser(low)
    os_family = _os(low)
    return (browser, _major_version(text, low, browser), os_family,
            _device_class(low, os_family))


@dataclass(frozen=True, slots=True)
class Binding:
    """The observable client binding presented alongside a session identifier."""

    address: str
    prefix24: str
    scope16: str
    browser: str
    version: str
    os_family: str
    device: str

    @property
    def core(self) -> tuple[str, str, str]:
        """Version-insensitive agent identity (browser family, OS, device class)."""
        return (self.browser, self.os_family, self.device)

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        """Hashable identity used for binding-equality and forking detection.

        The full address is included rather than only its prefix: two hosts
        inside one /24 that alternate within a session are two clients, and
        collapsing them onto their shared prefix would conceal exactly the
        interleaving that the fork invariant exists to find.
        """
        return (self.address, self.browser, self.version, self.os_family, self.device)


def binding_of(ip: str, user_agent: str | None) -> Binding:
    """Build the binding descriptor for one request."""
    browser, version, os_family, device = parse_user_agent(user_agent)
    return Binding(str(ip), ip_prefix24(ip), ip_scope16(ip), browser, version,
                   os_family, device)
