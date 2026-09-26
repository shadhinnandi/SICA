# SICA: Session Integrity and Continuity Analysis

SICA is a small, rule-based detector for **mid-session HTTP session hijacking**.
It reads the access log a web server already writes, rebuilds sessions, and
watches how the client "binding" of each session (IP address, network, browser,
operating system, device) changes from request to request. Three simple rules
score those changes, the scores are combined into a risk value, and a session is
flagged when its highest risk reaches a threshold that was calibrated on
attack-free traffic so that at most 1% of benign sessions alert. SICA uses no
machine learning, no attack labels for calibration, and constant work per
request. This README describes the project exactly as it exists in this folder.

---

## Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Threat Model](#3-threat-model)
4. [Core Idea: Binding Fork](#4-core-idea-binding-fork)
5. [System Architecture](#5-system-architecture)
6. [Input Data](#6-input-data)
7. [Session Reconstruction](#7-session-reconstruction)
8. [Client Binding / Fingerprinting](#8-client-binding--fingerprinting)
9. [Detection Rules](#9-detection-rules)
10. [V4, V5, V6 and Why They Were Not Used](#10-v4-v5-v6-and-why-they-were-not-used)
11. [Risk Calculation](#11-risk-calculation)
12. [Dataset-Calibrated Risk Threshold](#12-dataset-calibrated-risk-threshold)
13. [Complete Decision Process](#13-complete-decision-process)
14. [Full Mathematical Example 1: Legitimate User](#14-full-mathematical-example-1-legitimate-user)
15. [Full Mathematical Example 2: Hijacker Caught](#15-full-mathematical-example-2-hijacker-caught)
16. [Dataset and Benchmark](#16-dataset-and-benchmark)
17. [Experiments](#17-experiments)
18. [Results](#18-results)
19. [Performance](#19-performance)
20. [Why SICA Is Useful](#20-why-sica-is-useful)
21. [Limitations](#21-limitations)
22. [Reproducibility](#22-reproducibility)
23. [Project Structure](#23-project-structure)
24. [Final End-to-End Summary](#24-final-end-to-end-summary)

---

## 1. Project Overview

**Full name.** SICA stands for **Session Integrity and Continuity Analysis**.

**Security problem.** After a user logs in, a web application usually gives the
browser a session identifier (normally a cookie). From then on the server serves
anyone who presents that identifier. The identifier is a *bearer credential*: no
password is checked again. If an attacker steals it (for example through XSS,
network capture, malware or a leaked log) and replays it, the server sees a
perfectly valid session.

**Attack targeted.** SICA targets **mid-session HTTP session hijacking**: an
attacker replaying a stolen, already-authenticated session identifier while the
session is live.

**Information SICA uses.** Only fields that a standard access log contains: the
client IP address, the `User-Agent` header, the timestamp, the requested path,
the `Referer` header, the status code and the response size, plus a session
identifier per request. The three rules of the final detector read only the IP
address and the `User-Agent`.

**Information SICA does not need.** Packet payloads, TLS fingerprints,
JavaScript running in the browser, geolocation databases, token binding,
a history of each user's past sessions, or any cooperation from the client.

**Machine learning.** None. The rules and their severity constants are fixed.
The only quantities derived from data are three weights and one threshold, and
both are computed from attack-free calibration traffic with closed-form rules
(Sections 11 and 12). No attack label is read during calibration.

**Main idea.** A legitimate user who moves (new Wi-Fi, mobile network, DHCP
renewal) changes binding in one direction and does not go back. When a thief
uses the same session while the victim is still browsing, the two clients take
turns, so an earlier binding *reappears* after a different one. SICA scores
binding changes, grades them by how large they are, and treats a reappearing
binding as strong evidence.

**What SICA is not designed to detect.**

- login anomalies (suspicious logins compared with a user's history)
- general account takeover (for example with stolen passwords)
- SQL injection
- XSS payloads, or any other malicious request content
- attacks that produce no detectable binding difference

**The L4 limitation.** If the attacker sits behind the same NAT or proxy as the
victim (same public IP address) and also copies the victim's `User-Agent`
exactly, every request the attacker sends has the same binding as the victim's
requests. Nothing SICA observes differs, so this case (attacker level L4,
Section 3) cannot be detected by SICA or by any method that relies only on these
observable bindings.

---

## 2. Problem Statement

**A normal session.**

```
browser --login--> web server          (server issues session cookie S)
browser --request (cookie S)--> server
browser --request (cookie S)--> server
...
```

Every request carries S, and the access log records the client IP address and
`User-Agent` of each request.

**Mid-session hijacking.** At some point the attacker obtains S and starts
sending requests with it from their own machine. Two things can happen next:

- **Silent takeover:** the victim stops using the session (closes the tab, goes
  idle). Only the attacker's requests follow.
- **Concurrent hijacking:** the victim keeps browsing. The log now contains
  requests from two different clients mixed together under one session.

**Why simple IP binding is not enough.** Many applications "pin" a session to
its first IP address and end it if the address changes. That has problems:

- Legitimate users change address during a session: DHCP renewals, carrier-grade
  NAT pools, moving from Wi-Fi to a mobile network. An IP pin raises a false
  alarm every time.
- An attacker can appear similar to the victim: a nearby address, or even the
  same address behind a shared NAT, and a copied `User-Agent`.
- A pinning rule has no adjustable operating point. Its false-alarm rate is
  simply the rate at which legitimate clients move. In this project's benchmark,
  pinning to the exact IP address raised alarms on about 15% of benign sessions
  (Section 18).
- A hijacker may alternate with the legitimate client. A rule that only asks
  "did anything change?" cannot tell a single legitimate move from repeated
  switching between two clients.

**Research question.** Can mid-session hijacking be detected on the server side,
from the access log alone, at constant cost per request, by checking a small set
of declared continuity rules against bounded per-session state, without machine
learning and without attack-labelled training data, while keeping the benign
false-alarm rate at an operator-chosen budget?

SICA does not solve HTTP session hijacking in general. It addresses the narrower
case where the hijack leaves a visible trace in the session's client binding.

---

## 3. Threat Model

**Victim.** A user who has authenticated and holds a live session. The victim
may legitimately change IP address during the session, may receive a browser
version update, and may occasionally alternate between two network interfaces
(for example a dual-homed laptop). The victim cannot be in two network locations
for a long interleaved period.

**Attacker.** Has obtained a valid, already-authenticated session identifier by
some means outside the model (XSS, network capture, log leakage, malware). The
attacker replays it from a client they control.

The attacker **can**:
- choose any network position, including one close to the victim;
- forge any client-supplied header, including `User-Agent`;
- send requests to any endpoint the session allows.

The attacker **cannot**:
- compromise the server or modify its logs;
- make the victim's own client send the attacker's requests;
- see the server's weights or threshold.

**Web server and access logs.** The server runs SICA next to its normal logging.
It sees only what it already logs: IP address, `User-Agent`, timestamp, path,
status, response size, `Referer`, and the session identifier of each request.

**Attack modes.**

| Mode | What happens after the theft |
|---|---|
| `takeover` (silent takeover) | The victim sends nothing more. Only attacker requests follow. |
| `concurrent` (concurrent hijacking) | The victim keeps browsing. Victim and attacker requests are interleaved. |

**Attacker levels L0 to L5.** The level says how much of the victim's binding the
attacker reproduces. This is exactly what `sica/benchmark.py` implements. The
"victim binding" is the binding the victim shows at the theft point.

| Level | Attacker IP address | Attacker `User-Agent` |
|---|---|---|
| L0 | the attacker's own address, from a different /16 network than every address the victim used | the attacker's own |
| L1 | the attacker's own address, from a different /16 network than every address the victim used | copied from the victim |
| L2 | a synthetic address inside the victim's /16, but in a different /24 | the attacker's own |
| L3 | a synthetic address inside the victim's /24 (different host) | copied from the victim |
| L4 | exactly the victim's address (shared NAT or proxy) | copied from the victim |
| L5 | exactly the victim's address (shared NAT or proxy) | the attacker's own, which must differ from every agent string the victim used |

In the benchmark, "the attacker's own" address and agent come from another real
client in the same log (the donor, Section 16).

**Why L4 is fundamentally undetectable here.** At L4 the attacker's requests
carry the same IP address and the same `User-Agent` string as the victim's, so
their bindings are identical. V1 and V2 see no change, and V3 sees no second
binding to reappear. A silent takeover at L4 is literally the same log sequence
as the victim continuing to browse. No detector that looks only at these
bindings can separate the two. L4 is still part of every reported result so that
the blind spot is visible.

**L5** is also co-located (same IP), but the attacker's agent differs, so V1
still fires.

**Out of scope:** session fixation, replay of an already finished session,
single-request attacks (SICA needs at least one earlier request to compare
against), and deployments that already use cryptographic token binding.

---

## 4. Core Idea: Binding Fork

Here A and B are two different client bindings. A binding is the combination of
IP address and browser identity that the server sees on a request (Section 8).

**Legitimate mobility (one-way move):**

```
A A A A B B B B
```

The user was at A (for example home Wi-Fi), then moved to B (mobile network).
After the move, A never appears again.

**Concurrent hijacking:**

```
A A B A B A
```

A is the victim, B is the attacker. Because the victim keeps browsing, A comes
back after B has appeared. The session "forks" into two active clients, and an
earlier binding reappears.

A single client that moves cannot produce this pattern for long, because it
cannot be in two places at once. A live concurrent hijack cannot avoid it,
because the victim keeps sending requests from A.

**How V3 detects it: the 4-entry ring.** For each session the detector keeps a
small list, called the *ring*, of the most recent **distinct** binding keys it
has seen (at most 4). A binding key is
`(IP address, browser, browser major version, OS, device class)`. For every new
request:

1. Compute the request's binding key.
2. If it equals the key of the previous request, nothing changed: V3 = 0.
3. If it is different from the previous key **and it is already in the ring**,
   an earlier binding has returned while a different one was active: this is a
   *revisit*, and V3 = 1.
4. If it is different and not in the ring, it is a new binding (a one-way move
   so far): V3 = 0, and the key is added to the ring. When the ring already holds
   4 keys, the oldest one is dropped first.

The ring is bounded, so memory per session is fixed. The consequence is that a
binding that was pushed out by four newer distinct bindings is forgotten.

**Reference migration.** V1 and V2 compare each request with a *pinned* reference
binding. The first request of a session pins the reference. After a one-way move
(a changed binding that is not a revisit) the reference is re-pinned to the new
binding, so a user who moves once is charged once, not on every later request.
After a revisit the reference is **not** re-pinned, because when two bindings
alternate there is no basis for deciding which client is the owner.

---

## 5. System Architecture

```
                      attack-free calibration sessions
                                    |
                                    v
                    +-------------------------------+
                    | CALIBRATION (once per dataset) |
                    |  replay 1: unit weights       |
                    |   -> benign rates eps_i,      |
                    |      applicability gate,      |
                    |      weights w_i              |
                    |  replay 2: weights w_i        |
                    |   -> session peak risks       |
                    |   -> threshold tau (alpha=1%) |
                    +-------------------------------+
                                    | w_i, tau (frozen)
                                    v
HTTP access log
      |
      v
Log parsing  (sessionize.py: one row per request)
      |
      v
Session reconstruction  (sessionize.py)
      |
      v
Client binding per request  (fingerprint.py)
      |
      v
Per-session state: pinned binding, 4-entry ring  (detector.py)
      |
      v
Rule evaluation V1, V2, V3  (invariants.py)
      |
      v
Weighted risk  R_t = sum_i w_i * v_i  (detector.py)
      |
      v
Session peak risk  = max over the session's requests
      |
      v
Dataset-calibrated risk threshold tau
      |
      +--------------+
      |              |
      v              v
    ALLOW          ALERT (with the rules that fired)
```

**Blocks.**

- **Log parsing** reads each line of an Apache/Nginx "combined" log and keeps IP
  address, timestamp, requested path, status, bytes, referrer and `User-Agent`.
- **Session reconstruction** groups requests into sessions (Section 7). The
  session identifier plays the role of the session cookie, which access logs do
  not record.
- **Client binding** turns one request's IP address and `User-Agent` into a
  structured binding (Section 8).
- **Per-session state** holds the pinned reference binding, the key of the
  previous request, the ring of up to 4 distinct binding keys, and a few
  counters. It is created on the first request of a session.
- **Rule evaluation** computes V1, V2 and V3 for every request after the first
  (Section 9). Each rule returns a value between 0 and 1.
- **Weighted risk** combines the rule values with the calibrated weights
  (Section 11).
- **Session peak risk** is the largest request risk seen so far in the session.
- **Threshold and decision.** A session is ALERT when its peak risk is greater
  than or equal to the threshold, otherwise ALLOW (Sections 12 and 13).

**Calibration phase.** Before anything is evaluated, the weights and the threshold
are derived from a calibration set of sessions that contains no attacks. This is
done once per dataset (and, in the experiments, once per random seed).

**Evaluation phase.** The frozen detector (fixed weights and threshold) processes
the evaluation sessions request by request.

**Benign and attack traffic.** In the experiments, calibration sessions are
always benign (they may contain legitimate mobility). Evaluation sessions are
benign sessions plus sessions into which a hijack was injected (Section 16).
Labels are used only afterwards to compute metrics.

**Final decision.** One ALLOW or ALERT per session, plus an explanation string
listing the rules that fired.

---

## 6. Input Data

SICA reads web server access logs in the NCSA **combined** log format. This is a
real line from the W1 log (`data/W1/apache_sample_1.log`):

```
83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
```

and from the W2 log (`data/W2/nginx_real.log`):

```
93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0 "-" "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.21)"
```

**Fields**, as parsed by `sica/sessionize.py`:

| Field | Example | How it is used |
|---|---|---|
| IP address | `83.149.9.216` | kept; used by the binding (V2, V3) |
| timestamp | `17/May/2015:10:05:03 +0000` | parsed as `%d/%b/%Y:%H:%M:%S` (the time zone offset is ignored); used for ordering and sessionisation |
| request line | `GET /presentations/... HTTP/1.1` | only the path (second token) is kept; the HTTP method and protocol are read from the line but not stored |
| status | `200` | kept; not used by V1 to V3 |
| bytes | `203023` (`-` becomes 0) | kept; not used by V1 to V3 |
| referrer | `http://semicomplete.com/...` or `-` | kept; used only by the rejected rule V6 |
| User-Agent | `Mozilla/5.0 (...) Chrome/32.0.1700.77 Safari/537.36` | kept; used by the binding (V1, V3) |

Lines that do not match the format, or whose timestamp cannot be parsed, are
skipped. The parser also accepts a JSON-per-line variant, but both project
datasets use the combined format.

**Example of what the detector sees** (the three W1 lines above):

```
Request 1:  IP = 83.149.9.216
            User-Agent = Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) ... Chrome/32.0.1700.77 ...
            Path = /presentations/logstash-monitorama-2013/images/kibana-search.png

Request 2:  IP = 83.149.9.216
            User-Agent = (same as request 1)
            Path = /presentations/logstash-monitorama-2013/images/kibana-dashboard3.png
```

SICA works on server-side access logs. It never inspects packets or request
bodies.

---

## 7. Session Reconstruction

Access logs do not record cookies, so the benchmark rebuilds sessions from the
log itself (`sessionize.py`):

1. **Sort** all requests by timestamp.
2. **Group** requests by the pair `(IP address, User-Agent string)`. This pair is
   the ground-truth identity of "one client" in the benchmark.
3. **Cut** each group into sessions wherever the gap between two consecutive
   requests is longer than **1800 seconds (30 minutes)** of idle time.
4. **Keep** only sessions with **at least 7 requests** (every kept session then
   leaves room for a theft point and requests after it).
5. **Name** each session `IP|digest|n`, where `digest` is a 6-byte BLAKE2s hash of
   the `User-Agent` and `n` numbers the sessions of that client. The hash is
   deterministic across runs and machines.

The grouping key is only used to build the benchmark's ground truth. The detector
receives the session identifier and, for each request, the IP address and
`User-Agent`, exactly as a server would.

This yields 254 sessions (3,874 requests) for W1 and 3,126 sessions (43,307
requests) for W2.

**Calibration/evaluation split.** Sessions are ordered by the time of their first
request. The earlier half is the **calibration** set and the later half is the
**evaluation** set (temporal 50/50 split): 127 + 127 sessions for W1 and
1,563 + 1,563 for W2. Client-disjoint and random splits exist and are reported
in E5 as controls.

**Timestamp limitation.** The project's dataset checks found that the *minute*
field of both logs is degenerate: it is always `05` in W1, and `05` or `06` in
W2. As a result no reconstructed session is longer than 59 seconds, and every
time gap inside a session is an artefact of how the sample logs were generated,
not real user behaviour. In effect the 30-minute idle timeout separates a
client's requests at clock-hour boundaries. Because of this, no claim is made
about realistic timing, detection latency is reported in attacker *requests*,
never in seconds, and the two time-based rules (V4, V5) cannot be judged on this
data. V1, V2 and V3 read no timestamps, so the final detector is not affected.

---

## 8. Client Binding / Fingerprinting

`sica/fingerprint.py` turns one request into a `Binding` with seven fields:

| Level | Field | Rule |
|---|---|---|
| exact IP | `address` | the IP address as logged |
| /24 network | `prefix24` | first three octets of an IPv4 address (first three groups for IPv6) |
| /16 network | `scope16` | first two octets of an IPv4 address (first two groups for IPv6) |
| browser | `browser` | first match in an ordered token list: Edge, Opera, Chrome, Firefox, Safari, MSIE, AptHTTP, Wget, Curl, FeedReader, Bot, Library, otherwise Other |
| browser version | `version` | the major version number of that client, or empty if none is advertised |
| operating system | `os_family` | iOS, Android, Windows, macOS, ChromeOS, Ubuntu, Debian, Linux, otherwise Other |
| device | `device` | Mobile or Tablet for iOS/Android, Desktop for desktop systems, otherwise Other |

A missing or empty `User-Agent` becomes the explicit identity
`(unknown, "", unknown, unknown)`, so an agent that disappears mid-session counts
as a change.

Two derived identities are used:

- **agent core** = `(browser, os_family, device)`, used by V1;
- **binding key** = `(address, browser, version, os_family, device)`, used by V3.
  It includes the full address, so two different hosts in the same /24 that
  alternate are still recognised as two bindings.

**Why several network levels matter.** Addresses change for very different
reasons. A new address in the same /24 is typical of a DHCP lease renewal or NAT
pool rotation and is weak evidence. A different /24 in the same /16 usually means
a different access network in the same organisation or provider. A different /16
usually means the client left the network where the session started. Treating
all three alike would give a rule the false-alarm rate of the most common one.

**Example** (synthetic addresses from documentation ranges; the fields are what
`binding_of` returns):

```
Binding A:  IP = 203.0.113.25    /24 = 203.0.113    /16 = 203.0
            Browser = Chrome     Version = 120      OS = Windows   Device = Desktop

Binding B:  IP = 198.51.100.40   /24 = 198.51.100   /16 = 198.51
            Browser = Firefox    Version = 121      OS = Windows   Device = Desktop
```

Changed: the exact IP, the /24 and the /16 (so V2 would be 1.0), and the browser
family, Chrome to Firefox (so V1 would be 1.0 because the agent core changed).
OS and device are the same.

---

## 9. Detection Rules

Each rule returns a *violation degree* between 0 and 1 for one request. V1 and V2
compare the request's binding with the pinned reference binding of the session
(Section 4). The constants are fixed in `InvariantParams` in
`sica/invariants.py`; none were fitted to attack labels.

### V1: Agent Mutation

```
V1 = 1.0    if (browser, OS, device) differs from the pinned binding
V1 = 0.35   else if only the browser major version differs
V1 = 0.0    otherwise
```

A browser does not change family, operating system or device class between two
requests of the same live session; those are properties of the physical device
and installed software. A major-version change can happen (an automatic update
followed by a restart) but rarely keeps an in-memory session alive, so it is
treated as weak evidence (0.35) rather than no evidence.

### V2: Scope Discontinuity

```
V2 = 1.0    if the /16 network differs from the pinned binding
V2 = 0.45   else if the /24 network differs (same /16)
V2 = 0.15   else if the exact IP differs (same /24)
V2 = 0.0    otherwise
```

The hierarchy is exact IP inside /24 inside /16. The grading is what separates V2
from plain IP pinning: routine address changes cost little, while leaving the
original network costs a lot.

### V3: Binding Fork

```
V3 = 1.0    if the binding key differs from the previous request's key
            AND the key is already in the session's 4-entry ring
V3 = 0.0    otherwise
```

V3 is the rule that looks at the **shape** of binding changes rather than their
size (Section 4). A one-way move never triggers it. An interleaving of two
clients triggers it every time the earlier binding returns. This is why it is
useful for concurrent hijacking: an attacker who copies the victim's agent and
uses an address far away (L1) makes V1 silent, but as soon as the victim's next
request arrives, V3 fires.

### Applicability gate

An *applicable* request is one where a rule's precondition holds. For V1 that
means a recognisable `User-Agent` (`browser != "unknown"`); V2 and V3 are always
applicable. During calibration, the share of calibration requests on which each
rule is applicable is measured. A rule applicable on fewer than 1% of calibration
requests (`APPLICABILITY_FLOOR = 0.01`) is removed from the active set before
weighting. Without this gate, a rule that can never fire on a dataset would look
"extremely rare" and receive a very large weight. On both datasets all three
final rules pass the gate (V1 applicability: 0.955 on W1, 1.0 on W2). The gate
matters for the rejected V6 on W2, which has almost no referrers.

---

## 10. V4, V5, V6 and Why They Were Not Used

Three more rules are implemented in `sica/invariants.py`. They were developed and
evaluated during the project, and **rejected** from the final detector. The final
detector uses only V1, V2 and V3 (`DEFAULT_INVARIANTS`).

| Rule | What it checks | Why it was rejected |
|---|---|---|
| V4 transition velocity | a /16 change that happens faster than a 300 s "settle time" | Without geolocation it fires on the same event V2 already reports, counting one piece of evidence twice. Its 300 s settle time is longer than every session in these logs (all under 60 s), so it cannot be assessed here. |
| V5 rate discontinuity | a request arriving much faster than the session's own smoothed inter-arrival time | It reads time gaps, and the time gaps in these logs are generator artefacts (degenerate minute field). Its mean benign violation degree is 0.13 to 0.19 here, far higher than V1 to V3. |
| V6 navigation break | a same-site `Referer` pointing to a page the session never visited | On the development seeds it lowered ranking quality on W1. It cannot fire on W2, which has referrers on about 0.03% of requests, so the applicability gate removes it there. |

The final set was chosen on separate development seeds (100 to 119) by
threshold-free ROC AUC, required to agree across both datasets. V4 to V6 remain in
the code only because the ablation study (E3) adds each of them back, so that the
rejection can be checked from the stored results.

---

## 11. Risk Calculation

For request `t` of a session, the risk is

```
R_t = sum over active rules i of  w_i * v_i(t)
    = w1 * V1(t) + w2 * V2(t) + w3 * V3(t)
```

- `R_t` is the risk of request t, between 0 and 1.
- `v_i(t)` is the violation degree of rule i on request t (Section 9).
- `w_i` is the weight of rule i. The weights are positive and sum to 1.

The first request of a session only establishes the state; its risk is 0.

**Weights from benign traffic.** Calibration replays the attack-free calibration
sessions once with unit weights and measures, for each rule,

```
eps_i = mean of v_i(t) over all calibration requests after each session's first request
```

`eps_i` is the average violation degree on benign traffic, so a rule that fires
often (or fires with high degrees) has a large `eps_i`. The raw weight is the
natural logarithm

```
raw_i = ln( 1 / (eps_i + 0.01) )
```

and the weights are normalised over the active rules:

```
w_i = raw_i / sum_j raw_j
```

`0.01` is the fixed floor `EPSILON_FLOOR`, which stops a rule that never fires
on benign traffic from dominating. The logarithm (rather than `1/eps`) keeps the
weights bounded. Rare benign events get more weight, common ones get less. No
attack label and no evaluation session is used.

**Numbers from a stored run** (W1, seed 0, from
`results/tables/e1_calibration_runs.csv`):

| Rule | eps_i | eps_i + 0.01 | raw_i = ln(1/(eps_i+0.01)) | w_i = raw_i / 12.0336 |
|---|---:|---:|---:|---:|
| V1 | 0.001397 | 0.011397 | 4.4744 | **0.3718** |
| V2 | 0.008837 | 0.018837 | 3.9719 | **0.3301** |
| V3 | 0.017674 | 0.027674 | 3.5873 | **0.2981** |
| sum | | | 12.0336 | 1.0000 |

Averaged over the 30 reporting seeds the weights are about 0.371 / 0.332 / 0.297
on W1 and 0.370 / 0.334 / 0.296 on W2.

The detector also supports a "decayed accumulator" instead of the plain request
risk, and uniform weights instead of the logarithmic ones. Both are used only as
ablation variants (E3). The final detector uses the plain request risk and the
logarithmic weights.

---

## 12. Dataset-Calibrated Risk Threshold

SICA uses **one calibrated risk threshold per dataset**, not one per user. It is
computed from attack-free calibration sessions so that at most **α = 1%** of
benign sessions would alert.

**Procedure** (`calibrate` and `threshold_for_budget` in `sica/detector.py`):

1. Take the attack-free calibration sessions of the dataset (they contain
   legitimate mobility, Section 16).
2. Compute the weights `w_i` (Section 11).
3. Replay the calibration sessions a second time with those weights, through the
   same code path used in evaluation (including reference migration), and record
   each session's **peak risk** `P_s = max_t R_t`.
4. Choose the threshold `tau` from the list of peaks `P = {P_1, ..., P_N}`:

```
tau = the smallest observed value v in P such that
      number of sessions with P_s >= v   <=   alpha * N
```

   If no observed value satisfies this (for example when more than `alpha * N`
   sessions share the maximum peak), `tau` is set just above the largest peak, so
   nothing alerts.

5. Freeze the weights and `tau`, then process the evaluation traffic.

**Why not a simple (1 - α) percentile?** The risk takes only a few distinct values
(a weighted sum of a few graded rules), so many calibration sessions have exactly
the same peak. A percentile would often land on such a tied value, and the `>=`
test would then admit every tied session and exceed the budget. Scanning the
distinct observed values avoids that.

**Finite samples.** With N calibration sessions, achievable alarm rates are
multiples of 1/N. For W1, N = 127, so `alpha * N = 1.27` and at most 1 calibration
session may alert (0.79%). For W2, N = 1,563, so at most 15 may alert. Over all
60 main runs, the worst calibration alarm rate was 0.96%.

The budget is met on the calibration sessions by construction. On the evaluation
sessions it is only expected to transfer approximately (Section 18).

For W1 seed 0 the result is `tau = 0.628173`. This equals `w2 + w3` for that run:
at least one benign calibration session reached exactly "V2 = 1.0 and V3 = 1.0 on
the same request", which is what interface flapping across /16 networks produces.

---

## 13. Complete Decision Process

```
Request (IP, User-Agent, session id)
   |
   v
Binding (address, /24, /16, browser, version, OS, device)
   |
   v
V1, V2 against the pinned binding;  V3 from the previous key and the ring
   |
   v
Rule values v_i in [0, 1]
   |
   v
Weighted risk  R_t = w1*V1 + w2*V2 + w3*V3
   |
   v
Session peak risk  P = max(P, R_t)
   |
   v
Compare with the dataset-calibrated threshold tau
   |
   v
ALLOW  if P < tau
ALERT  if P >= tau
```

The decision is made on the **session peak risk**, not on a sum or average. The
peak starts at 0 and is updated after every request. A session alerts as soon as
one request's risk reaches `tau`, and the index of that first request is recorded.
After the rules are evaluated, the state is updated: the ring and the previous key
change if the binding changed, and the pinned binding is re-pinned only after a
one-way move.

**What an alert contains.** For every request the detector returns a record with
the session id, request index, the request risk, the session peak risk, each
rule's value, applicability flags, and an explanation string listing each rule
with a positive value, in this exact format:

```
V2_scope_discontinuity=1.00|V3_binding_fork=1.00
```

`results/summary/decisions_seed0.csv` shows the final per-session output for one
seed (seed 0 of E1). Real rows:

```
workload,seed,session_id,n_requests,truth,scenario,peak_risk,threshold,decision,alert_at_request,fired_at_peak
W1_web,0,62.225.70.202|68f9a3321324|1,33,hijacked,L1_concurrent,0.628173,0.628173,ALERT,14,V2_scope_discontinuity=1.00|V3_binding_fork=1.00
W1_web,0,193.104.184.225|3cbe7a10d1e9|1,7,hijacked,L0_takeover,0.701896,0.628173,ALERT,3,V1_agent_mutation=1.00|V2_scope_discontinuity=1.00
W1_web,0,88.103.19.195|71189d47e31b|1,7,benign,M1_handover:scope,0.33007,0.628173,ALLOW,,V2_scope_discontinuity=1.00
W1_web,0,208.115.113.88|a140f27eac68|8,25,benign,M4_flapping:scope,0.628173,0.628173,ALERT,15,V2_scope_discontinuity=1.00|V3_binding_fork=1.00
```

`truth` and `scenario` come from the benchmark and are not visible to the
detector. `alert_at_request` is the 0-based index of the first request whose risk
reached `tau`. The last row is a benign false alarm (Section 18).

---

## 14. Full Mathematical Example 1: Legitimate User

**This is an illustrative example.** The six requests are synthetic (documentation
IP ranges, a Chrome 120 on Windows `User-Agent`). The weights and threshold are
the real calibrated values of the stored W1, seed 0 run:

```
w1 = 0.3718   w2 = 0.3301   w3 = 0.2981   tau = 0.6282
```

The rule values and risks below were produced by running the project's own
`ContinuityMonitor` on this sequence with that configuration.

**Scenario.** A user browses from home Wi-Fi (binding A), then switches to a
mobile network with an address in a different /16 (binding B), and keeps
browsing. Browser, OS and device stay the same.

```
A = 203.0.113.25,  /24 203.0.113,  /16 203.0,   Chrome 120, Windows, Desktop
B = 198.51.100.40, /24 198.51.100, /16 198.51,  Chrome 120, Windows, Desktop
```

| Request | IP | /24 | /16 | Browser | Pinned before | Ring before | V1 | V2 | V3 | Risk R_t |
|---|---|---|---|---|---|---|--:|--:|--:|--:|
| 1 | 203.0.113.25 | 203.0.113 | 203.0 | Chrome 120 | (none) | (empty) | - | - | - | 0 (establishes session) |
| 2 | 203.0.113.25 | 203.0.113 | 203.0 | Chrome 120 | A | [A] | 0 | 0 | 0 | 0 |
| 3 | 203.0.113.25 | 203.0.113 | 203.0 | Chrome 120 | A | [A] | 0 | 0 | 0 | 0 |
| 4 | 198.51.100.40 | 198.51.100 | 198.51 | Chrome 120 | A | [A] | 0 | 1.0 | 0 | 0.3301 |
| 5 | 198.51.100.40 | 198.51.100 | 198.51 | Chrome 120 | B | [A, B] | 0 | 0 | 0 | 0 |
| 6 | 198.51.100.40 | 198.51.100 | 198.51 | Chrome 120 | B | [A, B] | 0 | 0 | 0 | 0 |

**Step by step.**

1. **Binding.** Requests 1 to 3 have binding A, requests 4 to 6 have binding B.
2. **V1.** The agent core `(Chrome, Windows, Desktop)` and the version 120 never
   change, so V1 = 0 on every request.
3. **V2.** On request 4 the /16 changes from `203.0` to `198.51` compared with
   the pinned binding A, so V2 = 1.0. Request 4 is a one-way move (B is not in
   the ring), so the pinned binding becomes B. Requests 5 and 6 match the new pin:
   V2 = 0.
4. **V3.** On request 4 the key changes, but B is not in the ring, so V3 = 0 and
   B is added: ring = [A, B]. Requests 5 and 6 have the same key as the previous
   request, so V3 = 0. A never returns.
5. **Weighted risk on request 4.**

```
R_4 = w1*V1 + w2*V2 + w3*V3
    = 0.3718*0 + 0.3301*1.0 + 0.2981*0
    = 0.3301
```

   All other requests have R_t = 0.
6. **Session peak risk.**

```
P = max(0, 0, 0, 0.3301, 0, 0) = 0.3301
```

7. **Calibrated threshold.** tau = 0.6282.
8. **Comparison.**

```
P = 0.3301 < tau = 0.6282   ->   ALLOW
```

The move is recorded (explanation `V2_scope_discontinuity=1.00` on request 4), but
a single one-way change of network, even across /16 networks, is not enough to
alert. For comparison, a DHCP change inside the same /24 would give
`R = 0.3301 * 0.15 = 0.0495`, and a browser update from Chrome 120 to 121 at the
same address would give `R = 0.3718 * 0.35 = 0.1301`. Both are far below tau.

---

## 15. Full Mathematical Example 2: Hijacker Caught

**This is an illustrative example**, computed with the same real W1 seed 0
configuration (`w1 = 0.3718, w2 = 0.3301, w3 = 0.2981, tau = 0.6282`) by running
the project's `ContinuityMonitor` on a synthetic sequence.

**Scenario.** Concurrent hijacking at level L1. The attacker uses an address in a
different /16 and copies the victim's `User-Agent` exactly, so V1 can never fire.

```
Victim   A = 203.0.113.25, /16 203.0,  Chrome 120, Windows, Desktop
Attacker B = 192.0.2.77,   /16 192.0,  Chrome 120, Windows, Desktop  (cloned agent)
```

The victim sends A A, the attacker starts after the theft, and the victim keeps
browsing, so the log shows `A A B A B A`.

| Request | Client | Binding | Pinned before | Ring before | V1 | V2 | V3 | Weighted Risk R_t |
|---|---|---|---|---|--:|--:|--:|--:|
| 1 | victim | A | (none) | (empty) | - | - | - | 0 (establishes session) |
| 2 | victim | A | A | [A] | 0 | 0 | 0 | 0 |
| 3 | attacker | B | A | [A] | 0 | 1.0 | 0 | 0.3301 |
| 4 | victim | A | B | [A, B] | 0 | 1.0 | **1.0** | 0.6282 |
| 5 | attacker | B | B | [A, B] | 0 | 0 | **1.0** | 0.2981 |
| 6 | victim | A | B | [A, B] | 0 | 1.0 | **1.0** | 0.6282 |

**Step by step.**

- **Request 3 (attacker's first request).** Key B differs from the previous key A
  and is not in the ring, so it looks like a one-way move: V3 = 0. Against the
  pinned A, the /16 changed: V2 = 1.0. The agent is identical: V1 = 0.

```
R_3 = 0.3718*0 + 0.3301*1.0 + 0.2981*0 = 0.3301
```

  B is added to the ring (ring = [A, B]) and, because this was not a revisit, the
  pinned binding becomes B. At this point the session looks exactly like the
  legitimate move of Example 1.

- **Request 4 (victim again).** Key A differs from the previous key B **and A is
  already in the ring**: this is a revisit, so **V3 fires**, V3 = 1.0. Against the
  pinned B, the /16 changed back: V2 = 1.0. The pinned binding is **not** changed
  (it stays B).

```
R_4 = 0.3718*0 + 0.3301*1.0 + 0.2981*1.0 = 0.6282
```

- **Request 5 (attacker).** Key B differs from the previous key A and is in the
  ring: revisit, V3 = 1.0. It matches the pinned B: V2 = 0.

```
R_5 = 0.3301*0 + 0.2981*1.0 = 0.2981
```

- **Request 6 (victim).** Same situation as request 4: `R_6 = 0.6282`.

**Session peak.**

```
P = max(0, 0, 0.3301, 0.6282, 0.2981, 0.6282) = 0.6282
```

**Comparison.**

```
P = 0.6282 >= tau = 0.6282   ->   ALERT at request 4 (index 3)
explanation: V2_scope_discontinuity=1.00|V3_binding_fork=1.00
```

The peak equals the threshold. That is not a rounding accident: in full precision
both are 0.6281733..., because tau for this run is itself the observed calibration
peak "V2 = 1 and V3 = 1 on one request". Since the rule is `P >= tau`, the session
alerts. The alert is raised on the first request after the theft on which the
victim reappears.

**Why this differs from legitimate mobility.** Up to request 3 the two examples
are identical. The difference is that in Example 1 binding A never returns, while
here it returns at request 4 while B is active. That return (the fork) is what
V3 measures.

**Two contrasting cases** (same configuration, computed the same way):

- If the attacker at request 3 had used their own browser (Firefox 121, level
  L0), V1 = 1.0 and V2 = 1.0 on request 3, so `R_3 = 0.3718 + 0.3301 = 0.7019 >=
  tau` and the session alerts on the attacker's very first request.
- If the same L1 attacker makes a **silent takeover** (log `A A B B B B`), the
  only non-zero risk is `R_3 = 0.3301`, so `P = 0.3301 < tau` and the session is
  ALLOWED. This is the same log pattern as a legitimate one-way move, which is why
  silent takeovers with a cloned agent are mostly missed (Section 18).

---

## 16. Dataset and Benchmark

### Datasets

| | W1 | W2 |
|---|---|---|
| File | `data/W1/apache_sample_1.log` | `data/W2/nginx_real.log` |
| Source | Elastic Examples, `Common Data Formats/apache_logs` | Elastic Examples, `Common Data Formats/nginx_logs` |
| Format | NCSA combined | NCSA combined |
| Traffic | Apache log of a personal/technical website: human browsing, feed readers, crawlers | Nginx demo/sample log, almost entirely Debian/Ubuntu APT clients |
| Requests parsed | 10,000 | 51,462 |
| Distinct IP addresses | 1,753 | 2,660 |
| Distinct `User-Agent` strings / agent cores | 558 / 40 | 136 / 22 |
| Requests with a referrer | 59.3% | 0.03% |
| Sessions (at least 7 requests) | 254 | 3,126 |
| Calibration + evaluation sessions | 127 + 127 | 1,563 + 1,563 |

Both files come from https://github.com/elastic/examples (Apache License 2.0,
see `data/LICENSE-APACHE-2.0.txt`). The only change is the file name.
SHA-256: W1 `f15c31e905f86c7b4b6ab44aee74d0a2086dce89f010187d983edea7ef0364ef`,
W2 `526832433ab552466dc8623390fd92dc052b4f301b2eec94836a5c42a46937df`.

**Preprocessing** is limited to parsing and sessionisation (Sections 6 and 7).
W2 is kept because it is hard for this method: one dominant agent family (so V1
has little to work with) and no referrers.

### Benign mobility injection (`apply_churn` in `sica/benchmark.py`)

Grouping by `(IP, User-Agent)` makes every real session binding-constant, which
would make the benign class unrealistically easy. So a declared share of benign
sessions receives a **legitimate** binding change, in **both** the calibration
and the evaluation halves:

| Type | What changes | Shape |
|---|---|---|
| M1 handover | the address changes at a random point and stays changed | one-way |
| M2 agent update | the browser major version changes (a real agent string from the same log with the same core and another version, or the version number incremented) | one-way |
| M3 combined | both of the above at the same point | one-way |
| M4 flapping | from a random point the address alternates between the old and a new one on every other request (dual-homed client) | interleaved |

Rates: 15% of benign sessions get M1, M2 or M3 (chosen uniformly), 5% get M4.
Each new address is in the same /24 (50%), a different /24 in the same /16 (30%)
or a different /16 (20%). These rates are assumptions, not measurements, and E4
sweeps them. M4 is the one benign behaviour that looks like a hijack, and it is
included on purpose so that its false-alarm cost is measured.

### Attack injection (`inject_session`, `inject_mixture`)

- **Which sessions.** Each evaluation session is targeted with probability 20%.
  In the main experiment the attack type is drawn uniformly from the 12
  combinations of level (L0 to L5) and mode (takeover, concurrent). The
  calibration half never receives attacks.
- **Theft point.** Drawn uniformly between `ceil(0.25 n)` (at least 2) and
  `floor(0.50 n)` for a session of n requests, and never moved afterwards.
- **Attacker requests are real.** They are copied from a different real client
  (a *donor* session in the same evaluation half), keeping its paths, statuses,
  sizes, referrers and time gaps. Only the IP address and `User-Agent` are replaced
  according to the level (Section 3). For L0/L1 the donor's /16 must differ from
  every /16 the victim used; for L5 the donor's agent must differ from every agent
  the victim used.
- **Length matching.** An injected session keeps exactly its original number of
  requests, so request count gives nothing away.
- **Takeover mode.** Victim requests after the theft point are removed and the
  attacker supplies the whole remaining tail.
- **Concurrent mode.** The attacker sends `k = clip(round(0.4 n), 3, 40)` requests
  (also limited by the space after the theft point and the donor's length), and
  the same number of victim requests after the theft point are removed. The
  session's last request is always kept as a victim request, so a victim request
  always follows the theft. The attacker's time gaps are compressed if needed so
  that its requests fall inside the victim's remaining window.
- **Refusals.** If a requested condition cannot be built for a session (too
  short, no admissible donor), it stays benign and the refusal is counted. Because
  of refusals the realised share of hijacked sessions is somewhat below 20% (on
  average 21.7 of 127 W1 evaluation sessions and 303.4 of 1,563 W2 sessions per
  seed).

---

## 17. Experiments

All experiments live in `sica/experiments.py` and are called by `run.py`.
Reporting seeds are 0 to 29 (E1, E2) or 0 to 19 (E3, E4, E5). Development seeds
100 to 119 were used only for design decisions and are disjoint from them.

| Experiment | Purpose |
|---|---|
| E0 | Corpus audit: dataset statistics, session yield for other timeout/length settings, agent mix |
| E1 | Main result at α = 1% over 30 seeds, per-scenario breakdown, false alarms by benign class, calibration details |
| E1b | False-alarm budget sweep, α from 0.001 to 0.10 (15 seeds) |
| E2 | SICA against non-ML baselines on identical sessions (30 seeds) |
| E3 | Ablation: remove each of V1 to V3, add back V4 to V6, each rule alone, uniform weights, no reference migration, accumulator evidence |
| E4 | Robustness: each attacker level and mode in isolation, sweeps of the benchmark assumptions, and the address-churn crossover against pinning |
| E5 | Leakage audit of the benchmark: single-feature AUCs, a feature-based reference detector, split sensitivity, 26 structural checks |
| E6 | Throughput, latency, scaling and memory of the detector |
| E7 | Paired Wilcoxon signed-rank tests with Holm correction, and a base-rate table |

**What each measures.**

- **Metrics** are per session (an operator responds to sessions): precision,
  recall, F1, false-positive rate (FPR, share of benign evaluation sessions that
  alert), ROC AUC and PR AUC over the session peak risk, and detection latency in
  attacker requests (how many attacker requests were sent up to and including the
  first alerting request). Accuracy is not reported. Each metric is averaged over
  seeds, with a 95% percentile bootstrap confidence interval of the mean.
- **E2 baselines.** Pinning rules, which alert on any change: `pin_ip`,
  `pin_prefix24`, `pin_scope16`, `pin_useragent`, `pin_useragent_core` (the same
  agent core V1 uses), `pin_ip_or_useragent`, `pin_ip_and_useragent`. They have no
  score, so no ROC AUC is reported for them. Scored rules calibrated to the same
  α with the same threshold procedure: `score_distinct_bindings`,
  `score_max_request_rate`, `score_burstiness`.
- **E3** recalibrates every variant fully, so each comparison is between two
  properly calibrated detectors.
- **E4 sweeps**: flapping rate, one-way mobility rate, attacker share of requests,
  attack prevalence, theft position, theft delay and minimum session length. The
  theft delay sweep is inert on these logs because no session exceeds 59 seconds.
- **E5** checks that the attack construction does not leave an easy shortcut
  (for example, session length or byte volume that reveals the label).
- **E7** tests whether SICA's per-seed differences from each baseline and
  ablation variant are consistent, and recomputes precision for realistic,
  much lower attack prevalences.

---

## 18. Results

These are the stored final results in `results/tables/` (α = 1%, mean over 30
seeds). They were produced by the full pipeline. During the final cleanup of the
code, E0, E1, E1b, E2 and E7 were regenerated with the reorganised code and
matched the stored values to within 1e-12. E3 to E6 were not re-run (seed spot
checks of E3, E4 and E5 matched to about 1e-16).

### Main result (E1)

| Dataset | ROC AUC [95% CI] | Recall | FPR | Precision | F1 | PR AUC | Alert after (attacker requests, median) |
|---|---|---|---|---|---|---|---|
| W1 | 0.884 [0.867, 0.900] | 0.358 | 0.85% | 0.906 | 0.497 | 0.742 | 1.4 |
| W2 | 0.851 [0.848, 0.855] | 0.229 | 0.56% | 0.920 | 0.362 | 0.667 | 2.5 |

**In plain language.**

- **ROC AUC 0.88 / 0.85:** if you pick one hijacked and one benign session at
  random, SICA gives the hijacked one a higher peak risk about 85% to 88% of the
  time.
- **FPR 0.85% / 0.56%:** fewer than 1 in 100 benign evaluation sessions raised an
  alert, close to the 1% budget.
- **Precision 0.91 / 0.92:** about 9 in 10 alerts were real hijacks, at the
  benchmark's roughly 17% to 19% attack share. At realistic, much lower attack
  rates precision falls (E7: about 0.30 at 1% prevalence).
- **Recall 0.36 / 0.23:** SICA caught about a third of the injected hijacks on W1
  and under a quarter on W2.

**The central trade-off.** SICA is designed around a low false-alert operating
point, and therefore misses a substantial fraction of attacks. Raising the budget
catches more attacks at the cost of more false alarms (E1b): at α = 5%, recall is
0.646 (W1) and 0.445 (W2) with FPR 4.4% and 3.9%.

### Where the false alarms come from (E1)

Unmodified real sessions produced no false alarms on either dataset. Almost all
false alarms come from benign **interface flapping across /16 networks** (M4),
which alerted in 58% of those sessions on both datasets (W1: 18 of 31; W2: 213 of
368, summed over seeds). On W1 a small number also come from address changes
across /16 networks (M1, M3) and from flapping inside one /16. Flapping produces
exactly the A/B interleaving that V3 looks for.

### Attacker levels (E4, recall at α = 1%, 20 seeds)

| Level | W1 takeover | W1 concurrent | W2 takeover | W2 concurrent |
|---|---|---|---|---|
| L0 own address (other /16), own agent | 0.882 | 0.993 | 0.405 | 0.893 |
| L1 own address (other /16), cloned agent | 0.002 | 0.700 | 0.001 | 0.718 |
| L2 same /16, other /24, own agent | 0.173 | 0.886 | 0.001 | 0.405 |
| L3 same /24, cloned agent | 0.002 | 0.015 | 0.001 | 0.005 |
| L4 same address, cloned agent | 0.002 | 0.015 | 0.001 | 0.007 |
| L5 same address, own agent | 0.002 | 0.891 | 0.001 | 0.485 |

- Detection is near complete against an attacker on another network who also
  uses a different browser (L0), especially while the victim keeps browsing.
- With a cloned agent (L1), the attack is caught about 70% of the time when the
  victim keeps browsing (V3), and almost never in a silent takeover, which looks
  like a legitimate move (Example 2).
- L5 shows that an address change is not required: an attacker at the victim's own
  address running a different client is caught 89% (W1) and 49% (W2) of the time
  in concurrent mode.
- L3 and L4 stay at the noise floor. L4 is undetectable by construction.
- Silent takeovers are mostly missed except at L0 (and partly L2 on W1).

### Baselines (E2)

| Detector | W1 recall | W1 FPR | W1 F1 | W2 recall | W2 FPR | W2 F1 |
|---|---|---|---|---|---|---|
| **SICA** | 0.358 | 0.85% | 0.497 | 0.229 | 0.56% | 0.362 |
| pin IP address | 0.711 | 15.3% | 0.576 | 0.695 | 15.0% | 0.599 |
| pin /24 | 0.551 | 7.4% | 0.575 | 0.523 | 7.4% | 0.570 |
| pin /16 | 0.367 | 3.0% | 0.479 | 0.342 | 3.0% | 0.467 |
| pin User-Agent string | 0.535 | 9.3% | 0.533 | 0.487 | 9.8% | 0.513 |
| pin agent core | 0.463 | 0.0% | 0.626 | 0.217 | 0.0% | 0.356 |
| pin IP or User-Agent | 0.862 | 19.6% | 0.610 | 0.855 | 20.0% | 0.637 |
| pin IP and User-Agent | 0.384 | 5.0% | 0.465 | 0.327 | 4.9% | 0.427 |

The scored baselines (distinct bindings, peak request rate, burstiness) detect
almost nothing at the same 1% budget (recall at most 0.034).

Read this table honestly:

- Pinning rules catch more attacks, but with false-alarm rates of 3% to 20%, set
  by how often legitimate clients move, with no way to lower them.
- Several pinning rules have a **higher F1** than SICA (for example pin IP and
  pin /24; the differences are significant in E7). SICA's advantage is a much
  lower and operator-chosen false-alarm rate, not a higher F1.
- `pin agent core` shows 0% FPR only because the benign mobility model never
  changes the browser family, OS or device. That number is an upper bound for this
  baseline, not a measurement.
- E4c shows the pinning rules' false-alarm rates growing with the amount of
  benign mobility, while SICA stays near its budget.

### Ablation (E3, 20 seeds)

| Variant | W1 F1 | W1 ROC AUC | W2 F1 | W2 ROC AUC |
|---|---|---|---|---|
| full SICA (V1, V2, V3) | 0.490 | 0.889 | 0.369 | 0.850 |
| without V1 | 0.173 | 0.831 | 0.186 | 0.820 |
| without V2 | 0.637 | 0.807 | 0.437 | 0.749 |
| without V3 | 0.578 | 0.886 | 0.269 | 0.844 |
| uniform weights | 0.415 | 0.886 | 0.339 | 0.848 |
| no reference migration | 0.417 | 0.886 | 0.218 | 0.844 |
| decayed accumulator | 0.175 | 0.880 | 0.143 | 0.841 |

The set V1 to V3 was chosen by ROC AUC, a threshold-free measure fixed in
advance. At the 1% operating point, removing V2 gives a higher F1 on both datasets
(with 0% FPR) and removing V3 gives a higher F1 on W1, while both lower ROC AUC.
These costs are reported, not hidden. On these reporting seeds, adding back V6
raised W1 ROC AUC to 0.902 and left W2 unchanged (V6 is gated out there), while
adding V4 or V5 did not raise ROC AUC on either dataset. The rejection decision
was made earlier, on the development seeds.

### Leakage audit (E5)

- No single session feature (request count, duration, bytes, gaps, error rate)
  separates the classes well: the largest single-feature ROC AUC is 0.590 (W1,
  total bytes) and 0.729 (W2, distinct paths, because W2 has only three URLs).
- A one-class detector over all eight of these features reaches F1 of only 0.017
  (W1) and 0.020 (W2) at the same budget. SICA's rules read none of these features.
- Client-disjoint and random splits give ROC AUC within about 0.025 of the
  temporal split (W1: 0.876 and 0.866 against 0.889; W2: 0.851 and 0.858 against
  0.850).
- All 26 structural checks pass (calibration is attack-free, partitions are
  disjoint, injected sessions keep their length, seed blocks are disjoint).

The six figures in `results/figures/` illustrate these results: architecture
(fig1), the binding-fork mechanism (fig2), recall per attacker level (fig3),
budget sweep against pinning (fig4), the mobility crossover (fig5) and the
leave-one-out ablation (fig6).

---

## 19. Performance

Measured in E6 (`results/tables/e6_efficiency.csv`, `e6_scaling.csv`). These are
measured results on one machine (CPython 3.11 on Linux x86_64, recorded in
`results/summary/e6_environment.json`). Absolute timings depend on the machine.

| | W1 | W2 |
|---|---|---|
| Throughput (median of 7 runs) | 58,808 requests/s | 52,007 requests/s |
| Median latency per request | 15.9 µs | 17.1 µs |
| 99th percentile latency | 48.2 µs | 52.1 µs |

That is roughly 55,000 requests per second and about 16 µs per request. The timing
covers the detector's per-request work on already-parsed requests. Log parsing and
sessionisation are timed separately.

**Constant time per request.** Each request does a fixed amount of work: one
`User-Agent` parse, three network comparisons, a membership test in a ring of at
most 4 keys, and a few scalar updates. E6 confirms that per-request cost stays flat
while the number of live sessions grows from 6 to 1,563.

**Memory per session.** The code's analytic bound on session state is 2,000 bytes
(about 2 KB): the pinned binding, scalars, the 4-entry ring and a 32-entry path
window used only by V6. The measured size of the Python objects is larger
(about 4.6 KB per session on W1 and 3.3 KB on W2) because of Python object
overhead. Either way it is fixed per session.

---

## 20. Why SICA Is Useful

- **No machine learning.** Three fixed rules, three weights and one threshold.
  Nothing to train, and the same input always gives the same output.
- **Server-log based.** It needs only the IP address and `User-Agent` that web
  servers already log. No client changes.
- **Lightweight.** Constant time per request and a few kilobytes per live session.
- **Interpretable.** Every alert names the rules that fired and their values, for
  example `V2_scope_discontinuity=1.00|V3_binding_fork=1.00`.
- **Calibrated false-alert budget.** The operator chooses α. The threshold is set
  from benign traffic to meet it, which pinning rules cannot offer.
- **Detects concurrent binding forks.** V3 catches a thief who copies the
  victim's browser, as long as the victim keeps browsing.
- **Tolerates some legitimate mobility.** A single address change, even across
  networks, or a browser version update does not by itself trigger an alert.

**Where it is weak.**

- Recall is low at the 1% operating point (0.36 and 0.23).
- Silent takeovers are mostly missed unless the attacker's binding is very
  different (L0).
- Attackers in the victim's /24 with a cloned agent (L3) or at the victim's
  address with a cloned agent (L4) are not caught.
- Benign interface flapping across networks produces the same pattern as a hijack
  and is the main source of false alarms.
- Several simple pinning rules reach a higher F1, at much higher false-alarm rates.

---

## 21. Limitations

- **Simulated attacks on real traffic.** The benign traffic is real. The hijacks
  are injected. Attacker requests are real requests from other clients of the same
  server with only the binding replaced, but the attacks themselves are
  constructed, and no real-world attack prevalence follows from them.
- **Benign mobility is also modelled.** The mobility rates and the 50/30/20 split
  of address-change sizes are assumptions (swept in E4). The model never changes
  the browser family, OS or device, which flatters `pin agent core`.
- **W1 is small.** 254 sessions (127 evaluated, about 22 hijacked per seed), so
  its confidence intervals are wide.
- **W2 is demo traffic.** Three placeholder URL paths, 65.8% of responses are 404,
  one dominant client family. It is not production traffic, despite its file name.
- **Timestamp limitation.** The minute field is degenerate in both logs, so no
  session is longer than 59 seconds and all time gaps are artefacts. No timing
  claims are made, and latency is given in attacker requests only.
- **V4 and V5 cannot be meaningfully evaluated** on this data, because both depend
  on real timing.
- **L4 is undetectable** with the available bindings, and L3 is not detected in
  practice.
- **Silent takeovers can be missed**, especially when the attacker clones the
  agent (L1 to L5 takeover recall is about 0.001 to 0.17).
- **FPR transfers only approximately.** The budget is guaranteed on the
  calibration sessions; on evaluation sessions individual seeds can exceed it
  (for example 1.8% on W1 seed 0), even though the averages (0.85%, 0.56%) are
  below 1%.
- **Session identity is reconstructed** from `(IP, User-Agent)`, because the logs
  contain no cookies or authentication data.
- **Not production evidence.** These results come from a controlled benchmark on
  public sample logs. They should not be read as evidence of performance in a
  production deployment.
- **Privacy.** The logs contain real, unmasked client IP addresses.

---

## 22. Reproducibility

**Requirements.** Python 3.10 or newer, and the packages in `requirements.txt`:
`numpy`, `pandas` (detector and evaluation), `scipy` (E7 tests), `matplotlib`
(figures), `pytest` (tests). No network access is needed after installation.

```bash
pip install -r requirements.txt
python run.py
```

**`python run.py`** (main workflow, about 6 minutes on the machine used for the
cleanup) runs, in order: E0, E1, E1b, E2, the per-session decisions file for
seed 0, E7, and then the report (LaTeX tables, figures, validation, summary). E3 to
E6 are not re-run; their stored tables are used. The command overwrites the
corresponding files in `results/` and `paper/tables/`.

Other options (they are mutually exclusive):

| Command | What it does | Approximate time |
|---|---|---|
| `python run.py --report` | rebuild paper tables, figures and summary from `results/tables/`, then validate | seconds |
| `python run.py --test` | run the 50 unit and regression tests in `tests/` | under a minute |
| `python run.py --all` | run every experiment E0 to E7, then the report | about 1 hour (E4 alone takes about 43 minutes) |
| `python run.py --dev` | development studies on seeds 100 to 119 (writes `dev_*` tables; not part of the reported results) | roughly 10 to 20 minutes |

Running `--all` re-measures E6 timings on your machine, so those numbers will
change. Every other result is deterministic given the seeds.

**Where outputs are stored.**

| Output | Location |
|---|---|
| Result tables (CSV), prefixed `e0_` to `e7_` | `results/tables/` |
| Figures (PDF and PNG) | `results/figures/` |
| One-page summary | `results/summary/summary.md` |
| Per-session decisions for seed 0 | `results/summary/decisions_seed0.csv` |
| Leakage checks, timing environment, sessionisation settings (JSON) | `results/summary/` |
| LaTeX table bodies and number macros for the paper | `paper/tables/` |

The validation step (`validate()` in `sica/report.py`) checks that all expected
tables, figures and paper tables exist and are mutually consistent (for example:
every run meets its budget on calibration, both datasets and all 30 seeds are
present, the attacker grid covers L0 to L5, no ML library is imported by the
detector code). It currently reports 73 checks passed, 0 failed.

To check the data files:

```bash
sha256sum data/W1/apache_sample_1.log data/W2/nginx_real.log
```

---

## 23. Project Structure

```
sica/                          (project root)
├── run.py                     the single entry point
├── README.md                  this document
├── LICENSE                    MIT licence for code and results
├── requirements.txt           Python dependencies
├── sica/                      the Python package
│   ├── __init__.py            package overview and main exports
│   ├── sessionize.py          parse access logs, rebuild sessions
│   ├── fingerprint.py         request -> binding (IP, /24, /16, browser, version, OS, device)
│   ├── invariants.py          V1, V2, V3 (final) and V4, V5, V6 (rejected, used in E3)
│   ├── detector.py            session state and ring, risk, calibration of weights and threshold, ALLOW/ALERT
│   ├── benchmark.py           benign mobility (M1 to M4) and hijack injection (L0 to L5, two modes)
│   ├── evaluation.py          calibrate-then-evaluate protocol, metrics, baselines
│   ├── experiments.py         experiments E0 to E7 and the development studies
│   └── report.py              paper tables, figures, summary, validation
├── data/
│   ├── W1/apache_sample_1.log
│   ├── W2/nginx_real.log
│   └── LICENSE-APACHE-2.0.txt licence of the two logs
├── results/
│   ├── tables/                39 result CSVs
│   ├── figures/               fig1 to fig6, PDF and PNG
│   └── summary/               summary.md, decisions_seed0.csv, JSON metadata
├── tests/
│   ├── conftest.py            makes the package importable for pytest
│   ├── test_sica.py           unit and protocol tests
│   └── test_regressions.py    tests for defects fixed during development
└── paper/
    ├── paper.tex              manuscript (reads figures from results/figures)
    ├── ref.bib                references
    ├── IEEEtran.cls           IEEE LaTeX class
    └── tables/                generated LaTeX tables and numbers.tex
```

The detector itself is the first four modules (`sessionize`, `fingerprint`,
`invariants`, `detector`). The other four exist to evaluate it and to produce the
paper's numbers.

---

## 24. Final End-to-End Summary

1. **Read web access logs.** Each line gives an IP address, timestamp, request
   path, status, size, referrer and `User-Agent`.
2. **Reconstruct sessions.** Group requests by client, split at 30 minutes of
   inactivity, and keep sessions with at least 7 requests.
3. **Extract the client binding** of every request: exact IP, /24, /16, browser,
   browser version, OS and device.
4. **Detect V1, V2 and V3 changes.** V1: did the browser, OS or device change?
   V2: how far did the network move? V3: did an earlier binding come back while a
   different one was active?
5. **Calculate the weighted risk** `R = w1*V1 + w2*V2 + w3*V3`, with weights that
   are larger for rules that are rare on benign traffic.
6. **Track the session peak risk**, the largest request risk so far.
7. **Compare with the dataset-calibrated risk threshold**, set on attack-free
   calibration sessions so that at most 1% of them would alert.
8. **Produce ALLOW or ALERT** for the session: ALERT when the peak risk is at least
   the threshold.
9. **Store the result and explanation**, for example
   `V2_scope_discontinuity=1.00|V3_binding_fork=1.00`, together with the request
   at which the alert was first raised.
10. **Evaluate against the benchmark.** Compare decisions with the injected
    ground truth over many seeds, attacker levels and baselines, and write the
    tables, figures and summary to `results/`.
