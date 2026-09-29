# SICA: Session Integrity and Continuity Analysis

SICA is a small rule/risk-based detector for possible **mid-session HTTP session
hijacking**. It only uses information a web server already writes to its access
log: the client IP address and the User-Agent string of each request.

SICA uses **no AI, no machine learning, no neural network and no external
detection model**. It is a fixed formula with three weights and one threshold,
so the same input always gives the same result.

## Problem

After login, a web application recognises the user only by a session ID (usually
a cookie). If an attacker steals that ID, they can reuse the valid session from
their own machine without ever logging in.

A normal session keeps roughly the same client: the same network and the same
browser. SICA watches every session for changes in these client characteristics
(the *client binding*) and raises the risk when they change.

## Objective

Build a simple, explainable detector that reads access-log requests session by
session and decides **ALLOW** or **ALERT** for each session, using the network,
the User-Agent and whether an earlier client comes back into the session.

## How SICA Works

```text
Server Access Logs  (data/W1_sample.csv, data/W2_sample.csv)
        |
        v
Group requests by session_id, keep their order
        |
        v
For each request: compare the client with the session's reference client
        |
        +--> User-Agent change   (browser / OS / device / version)
        +--> Network change      (same IP, /24, /16)
        +--> Old client back?    (binding fork)
        |
        v
Risk score for the request
        |
        v
Highest risk in the session  >=  0.6282 ?
        |
   +----+----+
   |         |
 ALLOW     ALERT
```

## Risk Formula

```text
risk = 0.3718 × user_agent_change
     + 0.3301 × network_change
     + 0.2981 × old_client_back

threshold = 0.6282
```

| Constant in `run.py` | Value | Meaning |
|---|---|---|
| `W_AGENT` | 0.3718 | User-Agent weight |
| `W_NETWORK` | 0.3301 | Network weight |
| `W_FORK` | 0.2981 | Binding fork (old client back) weight |
| `THRESHOLD` | 0.6282 | Alert threshold |

**User-Agent change**

| Situation | Score |
|---|---|
| browser, OS or device type changed | 1.00 |
| only the browser version changed | 0.35 |
| unchanged | 0.00 |

**Network change**

| Situation | Score |
|---|---|
| different /16 network (first two parts of the IP differ) | 1.00 |
| different /24 subnet inside the same /16 | 0.45 |
| new IP inside the same /24 | 0.15 |
| same IP | 0.00 |

**Old client back (binding fork)**

| Situation | Score |
|---|---|
| a client seen earlier in the session returns after a different client appeared | 1.00 |
| otherwise | 0.00 |

## Decision Rule

```text
highest request risk in the session >= 0.6282  ->  ALERT
highest request risk in the session <  0.6282  ->  ALLOW
```

A network change alone (0.3301) or a User-Agent change alone (0.3718) stays
below the threshold, because honest users do change networks or update
browsers. Both together (0.7019), or an old client returning from another
network (0.3301 + 0.2981 = 0.6282), reach it.

## Dataset

The original logs are public samples from the Elastic Examples repository
(Apache 2.0, see `data/LICENSE-APACHE-2.0.txt`):

| | Original log | Sample used by SICA |
|---|---|---|
| W1 | `data/W1/apache_sample_1.log` (Apache, 10,000 requests) | `data/W1_sample.csv`: 100 sessions, 1,485 requests |
| W2 | `data/W2/nginx_real.log` (Nginx, 51,462 requests) | `data/W2_sample.csv`: 100 sessions, 1,395 requests |

The logs contain no session cookies, so `make_samples.py` rebuilds sessions with
these project-specific rules:

- client identity = IP address + User-Agent
- a pause longer than 30 minutes starts a new session
- a session needs at least 7 requests
- the first 100 sessions (by start time) are kept

Sample columns: `session_id, time, ip, user_agent, path, attack`.

### Simulated Attack Cases

The original logs do not contain any confirmed real attacks. The project
therefore adds **simulated** hijacks: every 5th session (20 per dataset) gets
attacker requests, marked with `attack=1`. The attacker uses the IP address of another
session (the next one from a different /16 network). Four simulated types rotate:

| Type | What the attacker does |
|---|---|
| concurrent | own User-Agent, 2 requests in the middle, victim keeps browsing |
| concurrent, copied UA | same, but copies the victim's User-Agent |
| takeover | own User-Agent, replaces the second half, victim stops |
| takeover, copied UA | same, but copies the victim's User-Agent |

## Results

`python run.py --data`:

| Dataset | Sessions | Simulated hijacks | Detected | False alarms |
|---|---:|---:|---:|---:|
| W1 | 100 | 20 | 15 | 0 / 80 |
| W2 | 100 | 20 | 13 | 0 / 80 |

All concurrent hijacks are detected on both datasets. The takeovers with a
copied User-Agent are missed (risk 0.3301, the same as a normal network change).
On W2 two further takeovers are missed because the attacker's APT client differs
from the victim's only in version (risk 0.4602).

## Testing

`data/test_cases.csv` has 8 hand-made test cases. Each has an `expected` result.

| # | Test case | Expected | Risk |
|---|---|---|---|
| 1 | Normal session (same IP and browser) | ALLOW | 0.0000 |
| 2 | New IP in the same subnet (DHCP renewal) | ALLOW | 0.0495 |
| 3 | Network change only (Wi-Fi to mobile data) | ALLOW | 0.3301 |
| 4 | Browser version update only | ALLOW | 0.1301 |
| 5 | User-Agent change only (same IP) | ALLOW | 0.3718 |
| 6 | Network and User-Agent change together | ALERT | 0.7019 |
| 7 | Hijack with copied User-Agent, victim keeps browsing | ALERT | 0.6282 |
| 8 | Hijack from the same IP (shared NAT) with another browser, victim continues | ALERT | 0.6699 |

Current result: **Passed: 8/8**.

## Installation

Only Python 3 is needed (tested with Python 3.10). SICA uses only the standard
library (`csv`, `os`, `re`, `sys`), so there is nothing to install;
`requirements.txt` just says so. On macOS use `python3` if `python` is not found.

## Commands

| Command | What it does |
|---|---|
| `python run.py` | Opens the menu (datasets, test cases, manual test, risk formula, exit) |
| `python run.py --test` | Runs the 8 test cases, prints Expected / Got / PASS, writes `results/test_results.csv` |
| `python run.py --data` | Checks the W1 and W2 samples, writes `results/dataset_results.csv` |
| `python run.py --manual` | Lets you type the requests of one session by hand |
| `python make_samples.py` | Utility: rebuilds `data/W1_sample.csv` and `data/W2_sample.csv` from the original logs. Not needed for normal use. |

## Manual Faculty Demonstration

Run `python run.py --manual`. Enter a session ID, then for each request an IP and
a User-Agent. `chrome`, `chrome121`, `firefox`, `safari`, `iphone` and `curl` are
shortcuts for full User-Agent strings. Pressing Enter reuses the previous value.
Type `done` to finish.

**Normal case** (same IP, same User-Agent):

```text
Session ID: normal1
Request 1   IP: 203.0.113.25   User-Agent: chrome
Request 2   IP: <Enter>        User-Agent: <Enter>    -> Risk: 0.0000  ALLOW
Request 3   IP: done
Session normal1: 2 requests, highest risk 0.0000  ->  ALLOW
```

**Attack case** (victim, attacker, victim again):

```text
Session ID: attack1
Request 1   IP: 203.0.113.25   User-Agent: chrome     (victim)
Request 2   IP: 192.0.2.77     User-Agent: <Enter>    (attacker)
            Network change: Yes (different network)   -> Risk: 0.3301  ALLOW
Request 3   IP: 203.0.113.25   User-Agent: <Enter>    (victim returns)
            Old client back: Yes (binding fork)       -> Risk: 0.6282  ALERT
Request 4   IP: done
Session attack1: 3 requests, highest risk 0.6282  ->  ALERT
```

Step-by-step guides are in [`docs/RUNNING_GUIDE.md`](docs/RUNNING_GUIDE.md).

## Project Structure

```text
sica/
├── run.py                  detector + terminal interface (menu, --test, --data, --manual)
├── make_samples.py         rebuilds the W1/W2 samples from the original logs
├── requirements.txt        no third-party packages needed
├── README.md
├── concept.md              the idea behind SICA, explained simply
├── LICENSE
├── data/
│   ├── W1/apache_sample_1.log    original W1 log
│   ├── W2/nginx_real.log         original W2 log
│   ├── W1_sample.csv             100 sessions used by run.py
│   ├── W2_sample.csv             100 sessions used by run.py
│   ├── test_cases.csv            8 test cases with expected results
│   └── LICENSE-APACHE-2.0.txt
├── results/
│   ├── dataset_results.csv       one row per W1/W2 session
│   └── test_results.csv          one row per test case
├── docs/
│   ├── HOW_IT_WORKS.md           step-by-step flow through the code
│   ├── FUNCTIONS.md              every function and constant in run.py
│   └── RUNNING_GUIDE.md          how to run, test and demonstrate
└── paper/                        4-page course report (LaTeX and PDF)
```

## Limitations

- Log-based only: it sees IP and User-Agent, not packets, cookies or page content.
- Fixed weights and a fixed threshold; they are not tuned per website or user.
- The attacks in the datasets are simulated, not real incidents.
- Legitimate users also change networks or browsers, so single changes are
  deliberately allowed.
- An attacker who copies the victim's User-Agent is harder to separate from a
  normal network change.
- A hijacker who takes over completely, so the original client never returns,
  does not trigger the binding fork and may be missed.
- An attacker with the victim's exact IP and User-Agent cannot be seen at all.
- This is a course project, not a complete production security system.

## License

Code: MIT License (`LICENSE`). Data: Apache 2.0 (`data/LICENSE-APACHE-2.0.txt`).
