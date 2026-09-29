# How SICA Works, Step by Step

This follows the program from the moment you start it until it prints ALLOW or
ALERT. Every step names the function in `run.py` that does it.

```text
python run.py [--data | --test | --manual]
        |
        v
main block / menu()  ->  choose a mode
        |
        v
load_sessions()  or  manual input      (rows grouped by session)
        |
        v
check_session()  for each session
   |-- parse_agent()     User-Agent -> browser, version, OS, device
   |-- agent_score()     User-Agent change vs reference
   |-- network_score()   network change vs reference   (uses subnets())
   |-- fork check        old client back?
   |-- risk = 0.3718*agent + 0.3301*network + 0.2981*fork
   '-- update recent list, last client, reference
        |
        v
peak = highest risk in the session
        |
        v
decide(peak)  ->  ALLOW / ALERT
        |
        v
print on screen  +  save_csv() into results/
```

---

## Step 1: The program starts

- **In:** the command you typed, e.g. `python run.py --test`.
- **What happens:** Python loads the constants (weights, threshold, browser and
  OS rules) and runs the main block at the bottom of `run.py`.
- **Out:** the first command-line argument.
- **Function:** main block.

## Step 2: A mode is selected

- **In:** the argument, or your menu choice.
- **What happens:** `--data` → dataset mode, `--test` → test mode, `--manual` →
  manual mode. With no argument `menu()` shows options 1–5 and calls the chosen
  mode.
- **Out:** one of `run_datasets()`, `run_tests()`, `manual_test()`,
  `show_settings()`.
- **Function:** main block, `menu()`.

## Step 3: Data is loaded

- **In:** a CSV file. `data/W1_sample.csv` / `data/W2_sample.csv` have columns
  `session_id, time, ip, user_agent, path, attack`; `data/test_cases.csv` has
  `test_id, name, expected, ip, user_agent`. In manual mode the data comes from
  the keyboard instead.
- **What happens:** every row becomes a dictionary.
- **Out:** rows.
- **Function:** `load_sessions()` (files), `manual_test()` + `ask()` (keyboard).

## Step 4: Requests are grouped into sessions

- **In:** rows.
- **What happens:** rows with the same `session_id` (or `test_id`) are put in one
  list, in file order. Only `ip` and `user_agent` are passed to the detector.
  (The session IDs themselves were created earlier by `make_samples.py`, which
  rebuilt sessions from the original logs using IP + User-Agent, a 30-minute
  pause rule and at least 7 requests.)
- **Out:** `{session_id: [rows]}` → for each session a list of `(ip, user_agent)`.
- **Function:** `load_sessions()`; the list is built in `run_datasets()` /
  `run_tests()`.

## Step 5: The User-Agent is parsed

- **In:** a User-Agent string.
- **What happens:** the string is matched against the `BROWSERS`, `SYSTEMS` and
  `VERSION_AT` rules.
- **Out:** `(browser, version, os, device)`, e.g. `("Chrome", "120", "Windows", "Desktop")`.
  Together with the IP this is the **client**: `(ip, browser, version, os, device)`.
- **Function:** `parse_agent()`, called inside `check_session()`.

## Step 6: The client is tracked

- **In:** the client of the current request.
- **What happens:** for the first request of a session the client becomes the
  **reference** (who the session belongs to) and the **last client**, and the
  **recent list** starts with it. Its risk is 0.
- **Out:** session state: `ref`, `last`, `recent`.
- **Function:** `check_session()`.

## Step 7: The network change is calculated

- **In:** current IP and reference IP.
- **What happens:** both IPs are split into /16 and /24.
- **Out:** 1.0 (different /16), 0.45 (different /24), 0.15 (new IP same /24), 0.0 (same IP).
- **Function:** `network_score()` using `subnets()`.

## Step 8: The User-Agent change is calculated

- **In:** current client and reference client.
- **Out:** 1.0 (browser/OS/device changed), 0.35 (version only), 0.0 (same).
- **Function:** `agent_score()`.

## Step 9: Is an old client back? (binding fork)

- **In:** current client, last client, recent list.
- **What happens:** `changed = client != last`; `fork = changed and client in recent`.
- **Out:** 1.0 if the client came back after a different client, else 0.0.
- **Function:** `check_session()`.

## Step 10: The risk is calculated

- **In:** the three scores.
- **What happens:**
  `risk = 0.3718 × agent + 0.3301 × network + 0.2981 × fork`, rounded to 4 decimals.
- **Out:** one step record `{"agent", "network", "fork", "risk"}` per request.
- **Function:** `check_session()`.

After the risk, the session state is updated: a new client is added to the recent
list (maximum 4), the last client is updated, and if it was a one-way move (not a
fork) the reference moves to the new client.

## Step 11: The risk is compared with the threshold

- **In:** all step records of the session.
- **What happens:** `peak = max(risk)`; `peak >= 0.6282`?
- **Out:** the session's decision.
- **Function:** `decide()`, called from `run_datasets()`, `run_tests()` and
  `manual_test()`. In manual mode `describe()` also shows the decision for every
  single request.

## Step 12: ALLOW or ALERT

- **ALERT:** at least one request reached 0.6282.
- **ALLOW:** every request stayed below 0.6282.
- Test mode also compares the decision with the `expected` column → PASS/FAIL.
- Dataset mode also compares with the `attack` column → hijack detected or
  false alarm.

## Step 13: Results are shown and saved

- **Dataset mode:** prints sessions checked, alerts, hijacks detected and false
  alarms for W1 and W2, and writes `results/dataset_results.csv`
  (`dataset, session_id, requests, simulated_hijack, peak_risk, result`).
- **Test mode:** prints Expected / Got / PASS for each test and `Passed: 8/8`,
  and writes `results/test_results.csv`
  (`test_id, name, expected, got, risk, status`).
- **Manual mode:** only prints; nothing is saved.
- **Function:** `print()` in each mode, `save_csv()`.

---

## Worked trace: test case 7 (hijack, victim keeps browsing)

Rows of test 7 in `data/test_cases.csv`:

| # | IP | User-Agent |
|---|---|---|
| 1 | 203.0.113.25 | Chrome 120 on Windows |
| 2 | 203.0.113.25 | Chrome 120 on Windows |
| 3 | 192.0.2.77 | Chrome 120 on Windows (copied) |
| 4 | 203.0.113.25 | Chrome 120 on Windows |

Call victim client A and attacker client B.

| Req | Client | ref before | last before | recent before | agent | network | fork | risk | after |
|---|---|---|---|---|---|---|---|---|---|
| 1 | A | – | – | – | 0 | 0 | 0 | 0.0000 | ref=A, last=A, recent=[A] |
| 2 | A | A | A | [A] | 0 | 0 | 0 | 0.0000 | nothing changed |
| 3 | B | A | A | [A] | 0 | 1.0 | 0 | 0.3301 | new client, one-way: ref=B, last=B, recent=[A,B] |
| 4 | A | B | B | [A,B] | 0 | 1.0 | 1.0 | 0.6282 | fork: last=A, ref stays B |

Peak = 0.6282 ≥ 0.6282 → **ALERT**, which equals the expected value → **PASS**.
