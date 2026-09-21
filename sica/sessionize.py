"""Parse real web-server access logs and group requests into client sessions.

Two log dialects are supported: the Apache/Nginx *combined* format and the
JSON-per-line variant produced by structured logging.  Sessionisation follows
the standard idle-timeout convention: requests from one client identity are cut
into sessions wherever the inter-arrival gap exceeds ``idle_seconds``.

The client identity used for grouping is ``(remote address, User-Agent)``.  This
is a property of the *ground-truth construction* of the benchmark, not of the
detector: it defines which requests genuinely belong to one client, so that an
injected request can be labelled as not belonging to it.  The detector never
sees this grouping; it sees only the session identifier.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

import pandas as pd

__all__ = ["Request", "Session", "agent_digest", "parse_log", "sessionize",
           "load_sessions"]


def agent_digest(ua: str, nbytes: int = 6) -> str:
    """Stable short digest of a User-Agent string, for use inside a session identifier.

    ``hash()`` is **not** usable here.  CPython salts the hash of ``str`` per process unless
    ``PYTHONHASHSEED`` is pinned, so an identifier built from it changes between runs and
    between machines, which contradicts the reproducibility claim and makes identifier
    uniqueness a property of luck rather than of construction.  BLAKE2s is deterministic,
    depends on nothing outside its input, and is in the standard library.

    The default 6-byte digest gives 48 bits.  Over the ~3,100 sessions of the larger corpus
    the birthday collision probability is below 1e-10, against roughly 1-in-3 for the 24-bit
    truncation this replaces -- and a collision is not benign, because two sessions sharing
    an identifier would have their state merged inside the monitor and corrupt each other.
    """
    return hashlib.blake2s(str(ua).encode("utf-8", "replace"),
                           digest_size=nbytes).hexdigest()

_COMBINED = re.compile(
    r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) (\S+)(?: "(.*?)" "(.*?)")?')
_TSFMT = "%d/%b/%Y:%H:%M:%S"


@dataclass(slots=True)
class Request:
    ip: str
    ua: str
    ts: float
    path: str
    referrer: str
    status: int
    nbytes: int
    injected: int = 0          # ground-truth label: 1 iff this request is the attacker's


@dataclass(slots=True)
class Session:
    session_id: str
    client: tuple[str, str]            # ground-truth (ip, ua) of the session owner
    requests: list[Request] = field(default_factory=list)
    label: int = 0                     # 1 iff the session contains injected requests
    scenario: str = "benign"
    first_injected_index: int | None = None

    @property
    def n(self) -> int:
        return len(self.requests)


def _parse_ts(text: str) -> float | None:
    try:
        return pd.Timestamp(
            pd.to_datetime(text.split(" ")[0], format=_TSFMT)).timestamp()
    except Exception:
        return None


def parse_log(path: str, dialect: str = "combined") -> pd.DataFrame:
    """Parse an access log into a request table sorted by arrival time."""
    rows: list[tuple] = []
    with open(path, encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            if dialect == "json":
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ip, tstext = d.get("remote_ip", ""), d.get("time", "")
                request, status = d.get("request", ""), d.get("response", 0)
                size, referrer = d.get("bytes", 0), d.get("referrer", "-")
                ua = d.get("agent", "-")
            else:
                m = _COMBINED.match(line)
                if not m:
                    continue
                ip, tstext, request, status, size, referrer, ua = m.groups()
                referrer = referrer or "-"
                ua = ua or "-"
            ts = _parse_ts(str(tstext))
            if ts is None:
                continue
            parts = str(request).split(" ")
            url = parts[1] if len(parts) > 1 else str(request)
            try:
                nbytes = 0 if str(size) in {"-", ""} else int(size)
            except ValueError:
                nbytes = 0
            rows.append((str(ip), str(ua), float(ts), url, str(referrer),
                         int(status), nbytes))
    frame = pd.DataFrame(rows, columns=["ip", "ua", "ts", "path", "referrer",
                                        "status", "bytes"])
    return frame.sort_values("ts", kind="mergesort").reset_index(drop=True)


def sessionize(frame: pd.DataFrame, idle_seconds: float = 1800.0,
               min_requests: int = 6) -> list[Session]:
    """Cut the request table into per-client sessions of at least ``min_requests``."""
    out: list[Session] = []
    frame = frame.sort_values(["ip", "ua", "ts"], kind="mergesort")
    for (ip, ua), group in frame.groupby(["ip", "ua"], sort=False):
        gap = group.ts.diff()
        cut = (gap > idle_seconds) | gap.isna()
        sid_local = cut.cumsum()
        for local, sub in group.groupby(sid_local, sort=False):
            if len(sub) < min_requests:
                continue
            sub = sub.sort_values("ts", kind="mergesort")
            session = Session(session_id=f"{ip}|{agent_digest(ua)}|{int(local)}",
                              client=(ip, ua))
            session.requests = [
                Request(r.ip, r.ua, float(r.ts), r.path, r.referrer,
                        int(r.status), int(r.bytes))
                for r in sub.itertuples(index=False)
            ]
            out.append(session)
    out.sort(key=lambda s: s.requests[0].ts)
    return out


def load_sessions(path: str, dialect: str = "combined",
                  idle_seconds: float = 1800.0,
                  min_requests: int = 6) -> list[Session]:
    return sessionize(parse_log(path, dialect), idle_seconds, min_requests)
