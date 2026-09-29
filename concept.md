# SICA Concept Guide

This file explains the idea behind SICA in simple terms. Everything here matches
the current `run.py`.

---

## 1. What is session hijacking?

HTTP does not remember users between requests. After you log in, the website
gives your browser a **session ID** (normally in a cookie). Every later request
sends that ID, and the server treats whoever sends it as you.

**Session hijacking** means an attacker gets that session ID (for example through
cross-site scripting, a malicious extension, network sniffing or a leaked log)
and sends it from their own machine. The server sees a valid session ID, so the
attacker is inside your account without ever typing a password.

## 2. What SICA detects

SICA looks for **suspicious client changes during an existing session**: the same
session suddenly being used from a different network, a different browser, or
from two clients that take turns.

It does **not** try to detect every web attack. It does not look at passwords,
SQL injection, XSS payloads, page content or network packets. It only reads the
client IP address and the User-Agent string of each request in a session.

## 3. Client binding

A **client binding** is the description of "who is using this session" that the
server can see in its log. In SICA a client is:

```text
(IP address, browser, browser version, operating system, device type)
```

- The **network part** comes from the IP address.
- The **agent part** comes from the User-Agent string, for example
  `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0.0.0 Safari/537.36`
  becomes `Chrome, 120, Windows, Desktop`.

In the W1/W2 datasets this split is already done: `make_samples.py` stores each
request as one row with separate columns `ip_address, browser, browser_version,
operating_system, device_type`, so a client is simply those five values. Only
the manual test still receives a full User-Agent string and splits it with
`parse_agent()`.

A session is **many rows**, not one: every request of the session is kept in
order (`request_no` 1, 2, 3, ...), because a change can only be seen by
comparing one request with the earlier ones.

For every session SICA keeps:

- a **reference client**: the client the session currently belongs to
  (at the start, the client of the first request)
- the **last client** seen
- a **recent list** of the last 4 different clients in this session

Every new request is compared with the reference client.

## 4. Network binding

An IPv4 address like `203.0.113.25` has four parts:

- `/16` = the first two parts: `203.0` (roughly "which big network / provider")
- `/24` = the first three parts: `203.0.113` (roughly "which subnet")

| Change compared with the reference | Example | Network score |
|---|---|---|
| same IP | 203.0.113.25 → 203.0.113.25 | 0.00 |
| new IP in the same /24 | 203.0.113.25 → 203.0.113.80 | 0.15 |
| different /24, same /16 | 203.0.113.25 → 203.0.50.9 | 0.45 |
| different /16 | 203.0.113.25 → 192.0.2.77 | 1.00 |

Small moves (a DHCP address renewal) cost little. Jumping to a completely
different network costs the full score.

## 5. User-Agent binding

| Change compared with the reference | Example | User-Agent score |
|---|---|---|
| same browser, version, OS and device | Chrome 120 → Chrome 120 | 0.00 |
| only the major version changed | Chrome 120 → Chrome 121 | 0.35 |
| browser, OS or device type changed | Chrome/Windows → Firefox/Linux | 1.00 |

A version change can happen after a browser update, so it gets a smaller score.
A real user does not normally switch to a different browser or operating system
in the middle of one logged-in session.

## 6. Binding fork (old client back)

This is the most important idea in SICA.

```text
Legitimate move:     A  A  A  B  B  B      (A is left behind)

Hijack:              A  A  B  A  B  A
                           |  |
                           |  +-- Client A returns  -> binding fork
                           +----- Client B appears
```

A user who changes network (Wi-Fi to mobile data) moves **one way**: after the
change, the old client does not come back. When an attacker uses a stolen session
while the victim is still browsing, both clients use the same session, so the
old client keeps **coming back**. That return is the *binding fork*.

In the code: a request is a fork when its client is different from the last
client **and** is already in the session's recent list. The fork score is then 1.

Why it is the strongest signal: a single change has many innocent explanations,
but one client repeatedly switching back and forth is much harder to explain
with a single honest user. It does **not prove** an attack. For example, a laptop
that keeps switching between two networks can produce the same pattern. It is a
strong reason to look at the session, which is exactly what an ALERT means.

What happens to the reference client:

- one-way move to a new client → the reference moves to the new client, so an
  honest move is charged only once
- an old client comes back → the reference is **not** moved, because with two
  clients alternating we cannot tell which one is the owner

## 7. Risk calculation

For every request after the first one:

```text
risk = 0.3718 × user_agent_change
     + 0.3301 × network_change
     + 0.2981 × old_client_back
```

The risk is rounded to 4 decimals. The first request of a session always has risk
0 because there is nothing to compare it with yet.

Possible values you will see often:

| Situation | Calculation | Risk |
|---|---|---|
| nothing changed | 0 | 0.0000 |
| new IP in same /24 | 0.3301 × 0.15 | 0.0495 |
| version update | 0.3718 × 0.35 | 0.1301 |
| different /16 network | 0.3301 × 1 | 0.3301 |
| different browser/OS | 0.3718 × 1 | 0.3718 |
| old client back from another network | 0.3301 + 0.2981 | 0.6282 |
| old client back with another browser, same IP | 0.3718 + 0.2981 | 0.6699 |
| network and browser change together | 0.3718 + 0.3301 | 0.7019 |
| everything changes and old client back | 0.3718 + 0.3301 + 0.2981 | 1.0000 |

**Where the numbers come from.** The weights are fixed constants in `run.py`;
the program does not recompute them. They were derived once, in an earlier
version of the project, from attack-free W1 sessions: a check that almost never
fires on normal traffic is stronger evidence, so it gets a larger weight
(each raw weight was `ln(1 / (average score on normal requests + 0.01))`, then the
three were scaled to add up to 1). The User-Agent check fired least often on
normal traffic, so it has the largest weight.

## 8. Threshold

```text
highest risk in the session >= 0.6282  ->  ALERT
highest risk in the session <  0.6282  ->  ALLOW
```

`0.6282` is exactly network weight + fork weight (0.3301 + 0.2981). This means:

- a network change alone (0.3301) → ALLOW
- a User-Agent change alone (0.3718) → ALLOW
- network + User-Agent change together (0.7019) → ALERT
- old client returning from another network (0.6282) → ALERT

A session is decided by its **highest** request risk: one suspicious request is
enough for ALERT.

## 9. Complete workflow

1. **Input.** A CSV with one row per request (`session_id, request_no, timestamp,
   ip_address, browser, browser_version, operating_system, device_type, attack`)
   or requests typed by hand.
2. **Group.** Rows are grouped by `session_id`, keeping their order.
3. **Client.** Each row becomes a client (ip_address, browser, browser_version,
   operating_system, device_type). In manual mode the typed User-Agent is first
   split into these fields by `parse_agent()`.
4. **First request.** It becomes the reference client and the last client; risk 0.
5. **Every next request.**
   - compare its User-Agent with the reference → `user_agent_change`
   - compare its IP with the reference → `network_change`
   - is it different from the last client but already in the recent list? → `old_client_back`
   - calculate the risk
   - update the recent list, last client and (for one-way moves) the reference
6. **Session decision.** Highest risk ≥ 0.6282 → ALERT, otherwise ALLOW.
7. **Output.** Printed on screen and saved to `results/dataset_results.csv` or
   `results/test_results.csv`.

## 10. Normal example

Rafi browses from home, then his laptop switches to a phone hotspot.

```text
Request  IP              Browser      Reference     Risk     Why
1        203.0.113.25    Chrome 120   (set to A)    0        first request
2        203.0.113.25    Chrome 120   A             0        nothing changed
3        198.51.100.40   Chrome 120   A -> B        0.3301   different /16 network
4        198.51.100.40   Chrome 120   B             0        same as reference B
```

Highest risk 0.3301 < 0.6282 → **ALLOW**. A single one-way network change is
normal.

## 11. Attack example

An attacker steals Rafi's session cookie and copies his User-Agent, while Rafi
keeps browsing.

```text
Victim (A: 203.0.113.25, Chrome)
   |
   v
Attacker appears (B: 192.0.2.77, Chrome)     risk 0.3301  ALLOW  (looks like a normal move)
   |                                          reference moves to B
   v
Victim returns (A again)                      A != last client, A is in recent list
   |
   v
Binding fork = 1, network change vs B = 1
   |
   v
Risk = 0.3301 + 0.2981 = 0.6282  >=  0.6282
   |
   v
ALERT
```

The second request alone is not suspicious enough. The third request shows two
clients sharing one session, and that pushes the risk to the threshold.

## 12. Important limitation

If the attacker **takes over completely** (the victim logs off or stops using the
site), the old client never comes back, so there is no binding fork. If the
attacker also copies the User-Agent, the log looks exactly like a normal user
changing network: one request with risk 0.3301 → ALLOW. In the W1/W2 samples,
all 10 "takeover with copied User-Agent" cases are missed for this reason.

An attacker using the victim's exact IP (same NAT) and exact User-Agent produces
no change at all and cannot be detected from the log.

## 13. Course-project scope

SICA **does**:

- read access-log style requests (IP + User-Agent per session)
- score User-Agent changes, network changes and returning old clients
- decide ALLOW / ALERT with a fixed formula and threshold
- run on two small real-log samples with simulated hijacks, 8 test cases and a
  manual demo

SICA **does not**:

- see real cookies, packets, passwords or page content
- use AI, machine learning or trained models
- learn per-user behaviour or adapt its weights
- block or log out anyone; it only reports ALLOW / ALERT
- replace a full production security system
