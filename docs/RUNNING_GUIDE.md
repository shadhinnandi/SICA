# Running, Testing and Demonstrating SICA

All commands are run from the project folder (the one that contains `run.py`).
On macOS, type `python3` wherever this guide says `python` if `python` is not
found.

---

## 1. Check Python

```bash
python --version        # or: python3 --version
```

Any Python 3 works (tested with Python 3.10). No packages need to be installed:
`run.py` only uses the standard library, and `requirements.txt` just says so.

## 2. Normal program (menu)

```bash
python run.py
```

```text
==== SICA: Session Integrity and Continuity Analysis ====
1. Run datasets (W1, W2 samples)
2. Run test cases
3. Manual test
4. Show risk formula
5. Exit
Choose:
```

| Option | Does the same as |
|---|---|
| 1 | `python run.py --data` |
| 2 | `python run.py --test` |
| 3 | `python run.py --manual` |
| 4 | prints the risk formula, the score values and the decision rule |
| 5 | exits (`q` also works) |

After each option the menu appears again. Any other input just redraws the menu.
Ctrl+C quits at any time.

## 3. Automated tests

```bash
python run.py --test
```

- **Where the tests are:** `data/test_cases.csv`. Each row is one request; rows
  with the same `test_id` form one small session. Columns:
  `test_id, name, expected, request_no, ip_address, browser, browser_version,
  operating_system, device_type`.
- **expected:** the correct answer written by us in advance (ALLOW or ALERT).
- **got:** what the detector returns: `check_session()` scores every request,
  the highest risk is taken, and `decide()` turns it into ALLOW/ALERT.
- **PASS/FAIL:** PASS when Got equals Expected, otherwise FAIL.
- **8/8:** all eight tests gave the expected answer.

Output (shortened):

```text
Test 1: Normal session (same IP and browser)
  Expected: ALLOW
  Got:      ALLOW  (risk 0.0000)
  PASS
...
Test 7: Hijack with copied user-agent while the victim keeps browsing
  Expected: ALERT
  Got:      ALERT  (risk 0.6282)
  PASS
...
Passed: 8/8
Results saved to results/test_results.csv
```

| # | Test | Expected | Risk |
|---|---|---|---|
| 1 | Normal session (same IP and browser) | ALLOW | 0.0000 |
| 2 | New IP in the same subnet (DHCP renewal) | ALLOW | 0.0495 |
| 3 | Network change only (Wi-Fi to mobile data) | ALLOW | 0.3301 |
| 4 | Browser version update only | ALLOW | 0.1301 |
| 5 | User-agent change only (same IP) | ALLOW | 0.3718 |
| 6 | Network and user-agent change together | ALERT | 0.7019 |
| 7 | Hijack with copied user-agent while the victim keeps browsing | ALERT | 0.6282 |
| 8 | Hijack from the same IP (shared NAT) with another browser | ALERT | 0.6699 |

The program exits with code 0 when all tests pass and 1 otherwise.

## 4. Dataset mode

```bash
python run.py --data
```

- **W1:** `data/W1_sample.csv`, 100 sessions (1,485 requests) from an Apache log
  of a personal technical website.
- **W2:** `data/W2_sample.csv`, 100 sessions (1,395 requests) from an Nginx demo
  log, mostly Debian/Ubuntu package (APT) clients.
- In each, 20 sessions contain a **simulated** hijack (`attack=1` rows); the other
  80 are normal traffic from the real logs.
- Each file has **one row per request** (not one row per session), with the
  columns `session_id, request_no, timestamp, ip_address, browser,
  browser_version, operating_system, device_type, attack`. Open either file in
  Excel or Google Sheets and filter on one `session_id` to see a session's
  requests in `request_no` order.
- Every session goes through `check_session()`; the highest risk decides.

Output:

```text
Dataset: W1  (data/W1_sample.csv)
  Sessions checked : 100  (80 normal, 20 with a simulated hijack)
  Alerts           : 15
  Hijacks detected : 15/20
  False alarms     : 0/80

Dataset: W2  (data/W2_sample.csv)
  Sessions checked : 100  (80 normal, 20 with a simulated hijack)
  Alerts           : 13
  Hijacks detected : 13/20
  False alarms     : 0/80

Per-session results saved to results/dataset_results.csv
```

`results/dataset_results.csv` has one row per session:
`dataset, session_id, requests, simulated_hijack, peak_risk, result`.

## 5. Manual mode

```bash
python run.py --manual
```

| Prompt | What to type |
|---|---|
| `Session ID:` | any label, e.g. `demo1` (Enter → `demo`). It is only a name. |
| `IP:` | the client IP of this request. Enter = same IP as the previous request (the first request needs an IP). `done` (or `q`) = finish. |
| `User-Agent:` | a full User-Agent string, or a shortcut. Enter = same as the previous request. `done` (or `q`) = finish. |

Shortcuts (not case-sensitive):

| Shortcut | Meaning |
|---|---|
| `chrome` | Chrome 120 on Windows desktop |
| `chrome121` | Chrome 121 on Windows desktop (version update) |
| `firefox` | Firefox 121 on Linux desktop |
| `safari` | Safari 17 on macOS |
| `iphone` | Safari on iPhone (mobile) |
| `curl` | the curl command-line tool |

After request 1 the program only records the client. From request 2 on it prints
the network change, User-Agent change, old-client-back check, the risk and the
ALLOW/ALERT for that request. After `done` it prints the session result (highest
risk) if at least two requests were entered. Manual mode does not save a file.

## 6. Rebuilding the samples

```bash
python make_samples.py
```

This reads the original logs (`data/W1/apache_sample_1.log`,
`data/W2/nginx_real.log`), rebuilds sessions (IP + User-Agent, new session after
a 30-minute pause, at least 7 requests), keeps the first 100 per dataset, adds a
simulated hijack to every 5th session, splits every User-Agent into
`browser, browser_version, operating_system, device_type` (with `parse_agent()`
from `run.py`), drops the columns SICA does not use (URL path, raw User-Agent)
and overwrites `data/W1_sample.csv` and `data/W2_sample.csv`. It is deterministic, so the files come out the same every
time. **You do not need to run it**; the samples are already in `data/`. Only run
it if a sample file is deleted or damaged.

---

# Faculty Demonstration Script

Start with:

```bash
python run.py --manual
```

(Or `python run.py` and choose 3.) Type exactly what is shown after each prompt.
`<Enter>` means just press Enter.

## Demonstration 1: Normal session

```text
Session ID: normal1

Request 1
  IP: 203.0.113.25
  User-Agent: chrome
  First request: client recorded for this session (risk 0)

Request 2
  IP: <Enter>
  User-Agent: <Enter>
  Network change    : No
  User-agent change : No
  Old client back   : No
  Risk: 0.0000   Threshold: 0.6282   ->  ALLOW

Request 3
  IP: done

Session normal1: 2 requests, highest risk 0.0000  ->  ALLOW
```

**Say:** "Same session, same IP, same browser. Nothing changed, so the risk is 0
and the session is allowed."

## Demonstration 2: Hijacking

Run `python run.py --manual` again.

```text
Session ID: attack1

Request 1                          <- the victim
  IP: 203.0.113.25
  User-Agent: chrome
  First request: client recorded for this session (risk 0)

Request 2                          <- the attacker with the stolen cookie
  IP: 192.0.2.77
  User-Agent: <Enter>
  Network change    : Yes (different network)
  User-agent change : No
  Old client back   : No
  Risk: 0.3301   Threshold: 0.6282   ->  ALLOW

Request 3                          <- the victim is still browsing
  IP: 203.0.113.25
  User-Agent: <Enter>
  Network change    : Yes (different network)
  User-agent change : No
  Old client back   : Yes (binding fork)
  Risk: 0.6282   Threshold: 0.6282   ->  ALERT

Request 4
  IP: done

Session attack1: 3 requests, highest risk 0.6282  ->  ALERT
```

**Say:** "When the attacker appears, it looks like a normal network change, so the
risk rises to 0.3301 but stays below the threshold. When the victim comes back,
two different clients are clearly taking turns in one session. That is a binding
fork: 0.3301 + 0.2981 = 0.6282, which reaches the threshold, so SICA raises an
ALERT."

## Optional extras

- `python run.py --test` → shows all 8 cases with Expected / Got / PASS and
  `Passed: 8/8`.
- Menu option 4 → shows the formula on screen.
- Network + browser change in one step: request 1 `203.0.113.25` / `chrome`,
  request 2 `192.0.2.77` / `firefox` → risk 0.7019 → ALERT.
