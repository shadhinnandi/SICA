# Function Reference

Every function and constant in `run.py`, in the order they appear in the file,
followed by the helper script `make_samples.py`.

---

## Constants in `run.py`

| Name | Value | Meaning |
|---|---|---|
| `W_AGENT` | 0.3718 | Weight of the User-Agent change |
| `W_NETWORK` | 0.3301 | Weight of the network change |
| `W_FORK` | 0.2981 | Weight of the binding fork (old client back) |
| `THRESHOLD` | 0.6282 | Risk at or above which a session gets ALERT |
| `VERSION_ONLY` | 0.35 | User-Agent score when only the browser version changed |
| `SAME_16` | 0.45 | Network score for a new /24 subnet inside the same /16 |
| `SAME_24` | 0.15 | Network score for a new IP inside the same /24 |
| `RECENT` | 4 | How many different clients a session remembers for the fork check |
| `HERE` | folder of `run.py` | Makes file paths work from any working directory |
| `DATASETS` | `{"W1": "data/W1_sample.csv", "W2": "data/W2_sample.csv"}` | Samples checked by `--data` |
| `TEST_FILE` | `data/test_cases.csv` | Test cases used by `--test` |
| `RESULTS` | `results` | Folder where result CSVs are written |
| `BROWSERS` | list of (name, tokens, not_tokens) | Rules to recognise the browser; checked top to bottom, first match wins (Edge before Chrome, Chrome before Safari, because Edge and Chrome also contain "Chrome"/"Safari" in their strings) |
| `SYSTEMS` | list of (name, tokens) | Rules to recognise the operating system, first match wins |
| `VERSION_AT` | dict browser → markers | Where each browser writes its version, e.g. Chrome after `chrome/` |
| `AGENTS` | dict shortcut → full User-Agent | Shortcuts for the manual test: `chrome`, `chrome121`, `firefox`, `safari`, `iphone`, `curl` |

The three risk components each take a value between 0 and 1:

| Component | Values |
|---|---|
| `agent` (user_agent_change) | 1.0 browser/OS/device changed, 0.35 version only, 0.0 same |
| `network` (network_change) | 1.0 different /16, 0.45 different /24, 0.15 new IP in same /24, 0.0 same IP |
| `fork` (old_client_back) | 1.0 an earlier client returned after a different one, 0.0 otherwise |

Constants in `make_samples.py` (used only when rebuilding the samples):

| Name | Value | Meaning |
|---|---|---|
| `SOURCES` | W1 and W2 original log paths | Input logs |
| `N_SESSIONS` | 100 | Sessions kept per dataset |
| `MIN_REQUESTS` | 7 | Minimum requests for a session to be kept |
| `IDLE_GAP` | 1800 s (30 min) | Session timeout: a longer pause starts a new session |
| `ATTACKS` | 4 attack types | Rotated over the simulated hijacks |
| `LOG_LINE` | regular expression | Reads one Apache/Nginx combined-format log line |

---

## Functions in `run.py`

### Function: `parse_agent(ua)`

**Purpose:** Turn a raw User-Agent string into the four facts SICA compares.

**Inputs:** `ua`, a User-Agent string such as
`Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0.0.0 Safari/537.36`.

**Output:** a tuple `(browser, version, os, device)`, e.g.
`("Chrome", "120", "Windows", "Desktop")`.

**How it works:**
1. If the string is empty, `-`, `nan` or `unknown`, return
   `("unknown", "", "unknown", "unknown")`.
2. Lower-case the string.
3. Browser: go through `BROWSERS`; the first entry whose tokens appear (and whose
   `not_tokens` do not) gives the name. Otherwise `"Other"`.
4. OS: go through `SYSTEMS` the same way. Otherwise `"Other"`.
5. Device: iOS/Android → `Mobile` (if the string has "mobile" or "iphone") or
   `Tablet`; any other known OS → `Desktop`; unknown OS → `Other`.
6. Version: for the browser's markers in `VERSION_AT`, find the marker and take
   the first number after it (the major version). Empty if none is found.

**Called by:** `check_session()`.

---

### Function: `subnets(ip)`

**Purpose:** Get the /16 and /24 network parts of an IP address.

**Inputs:** `ip`, e.g. `"203.0.113.25"`.

**Output:** a tuple `(net16, net24)`, e.g. `("203.0", "203.0.113")`.

**How it works:** For IPv4 it splits on `.` and joins the first two and first
three parts. For IPv6 (contains `:`) it uses the first two and three blocks. If
the address does not have 4 parts, the whole address is returned for both.

**Called by:** `network_score()`.

---

### Function: `agent_score(client, ref)`

**Purpose:** Score how much the User-Agent changed compared with the reference.

**Inputs:** `client` and `ref`, both tuples `(ip, browser, version, os, device)`.

**Output:** `1.0`, `0.35` (`VERSION_ONLY`) or `0.0`.

**How it works:** If browser, OS or device differ → 1.0. Else if only the
version differs → 0.35. Else → 0.0.

**Called by:** `check_session()`.

---

### Function: `network_score(client, ref)`

**Purpose:** Score how far the IP address moved compared with the reference.

**Inputs:** `client` and `ref`, tuples whose first element is the IP.

**Output:** `1.0`, `0.45` (`SAME_16`), `0.15` (`SAME_24`) or `0.0`.

**How it works:** Uses `subnets()` on both IPs. Different /16 → 1.0; same /16
but different /24 → 0.45; same /24 but different IP → 0.15; same IP → 0.0.

**Called by:** `check_session()`.

---

### Function: `check_session(requests)`

**Purpose:** The detector. Score every request of one session.

**Inputs:** `requests`, a list of `(ip, user_agent)` pairs in the order they
happened.

**Output:** a list with one dictionary per request:
`{"agent": ..., "network": ..., "fork": ..., "risk": ...}`.

**How it works:**
1. Start with no reference client, no last client, empty recent list.
2. For each request build `client = (ip, browser, version, os, device)` using
   `parse_agent()`.
3. **First request:** it becomes the reference and the last client, the recent
   list becomes `[client]`, and all scores are 0.
4. **Later requests:**
   - `changed` = client differs from the last client
   - `fork` = `changed` and the client is already in the recent list
   - `agent = agent_score(client, ref)`, `net = network_score(client, ref)`
   - `risk = W_AGENT*agent + W_NETWORK*net + W_FORK*fork`, rounded to 4 decimals
5. **Update after a change:** add the client to the recent list if it is new
   (keep only the last `RECENT` = 4), set it as the last client, and, only if it
   was *not* a fork, make it the new reference (a one-way move is charged once).
   A returning old client does not become the reference.

**Called by:** `run_datasets()`, `run_tests()`, `manual_test()`.

---

### Function: `decide(risk)`

**Purpose:** Apply the threshold.

**Inputs:** a risk value.

**Output:** `"ALERT"` if `risk >= THRESHOLD` (0.6282), otherwise `"ALLOW"`.

**Called by:** `run_datasets()`, `run_tests()`, `describe()`, `manual_test()`.

---

### Function: `load_sessions(path, key)`

**Purpose:** Read a CSV file and group its rows into sessions.

**Inputs:** `path` (relative to the project folder) and `key`, the column that
identifies a session (`"session_id"` for W1/W2, `"test_id"` for test cases).

**Output:** a dictionary `{session_key: [row, row, ...]}`; each row is a
dictionary of the CSV columns. Rows keep their file order.

**How it works:** Opens the file with `csv.DictReader` and appends each row to
the list of its key.

**Called by:** `run_datasets()`, `run_tests()`.

---

### Function: `save_csv(name, header, rows)`

**Purpose:** Write a result file.

**Inputs:** file `name`, a `header` list and a list of `rows`.

**Output:** the relative path of the file written (e.g.
`results/test_results.csv`).

**How it works:** Creates the `results/` folder if needed, then writes the
header and rows with `csv.writer`. An existing file is overwritten.

**Called by:** `run_datasets()`, `run_tests()`.

---

### Function: `run_datasets()`

**Purpose:** Dataset mode (`--data` or menu option 1).

**Inputs:** none (uses `DATASETS`).

**Output:** prints a summary per dataset and writes
`results/dataset_results.csv`. Returns nothing.

**How it works:** For W1 and W2:
1. `load_sessions(path, "session_id")`.
2. For each session: `check_session()` on its (ip, user_agent) pairs, take the
   highest risk (`peak`), `decide(peak)`.
3. A session is a simulated hijack if any row has `attack == "1"`.
4. Count alerts, detected hijacks, and false alarms (ALERT on a normal session).
5. Print: sessions checked, alerts, hijacks detected, false alarms.
6. After both datasets, save one row per session:
   `dataset, session_id, requests, simulated_hijack, peak_risk, result`.

**Called by:** `menu()` and the `--data` argument.

---

### Function: `run_tests()`

**Purpose:** Automated test mode (`--test` or menu option 2).

**Inputs:** none (uses `TEST_FILE`).

**Output:** prints each test and `Passed: X/Y`, writes
`results/test_results.csv`, and returns `True` if every test passed.

**How it works:**
1. `load_sessions(TEST_FILE, "test_id")`; each test is a small session.
2. For each test: `check_session()`, highest risk, `decide()` → **Got**.
3. **Expected** is the `expected` column of the test's first row.
4. PASS if Got equals Expected, otherwise FAIL.
5. Save `test_id, name, expected, got, risk, status`.

With `--test` the program exits with code 0 when all pass and 1 otherwise.

**Called by:** `menu()` and the `--test` argument.

---

### Function: `describe(step)`

**Purpose:** Print the result of one request in the manual test.

**Inputs:** one dictionary from `check_session()`.

**Output:** printed lines (returns nothing):
```text
  Network change    : Yes (different network)
  User-agent change : No
  Old client back   : No
  Risk: 0.3301   Threshold: 0.6282   ->  ALLOW
```

**How it works:** Translates the score values into words with two small
dictionaries and prints the risk with `decide()` applied to that request.

**Called by:** `manual_test()`.

---

### Function: `ask(prompt)`

**Purpose:** Read one line of keyboard input safely.

**Inputs:** the prompt text.

**Output:** the typed text without surrounding spaces, or `"done"` if input
ends (EOF, e.g. when input is piped from a file).

**Called by:** `manual_test()`, `menu()`.

---

### Function: `manual_test()`

**Purpose:** Manual mode (`--manual` or menu option 3). Lets you type a session.

**Inputs:** keyboard input: a session ID, then an IP and a User-Agent per request.

**Output:** printed analysis after every request and a final session result.

**How it works:**
1. Ask for a session ID (Enter → `demo`). The ID is only a label.
2. Loop for request 1, 2, 3, ...:
   - `IP:` typed IP; Enter reuses the previous IP (the first request must have
     one); `done` or `q` finishes.
   - `User-Agent:` typed string or a shortcut from `AGENTS`; Enter reuses the
     previous one (`-`, i.e. unknown, for the first request); `done` or `q`
     finishes.
   - Request 1 prints "First request: client recorded for this session (risk 0)".
   - Later requests run `check_session()` on everything typed so far and
     `describe()` the last request.
3. If at least two requests were entered, print the highest risk and the
   session's ALLOW/ALERT.

**Called by:** `menu()` and the `--manual` argument.

---

### Function: `show_settings()`

**Purpose:** Menu option 4. Print the risk formula, the score values and the
decision rule, all taken from the constants.

**Called by:** `menu()`.

---

### Function: `menu()`

**Purpose:** The interactive menu shown by `python run.py`.

**How it works:** Repeatedly prints

```text
1. Run datasets (W1, W2 samples)
2. Run test cases
3. Manual test
4. Show risk formula
5. Exit
```

and calls `run_datasets()`, `run_tests()`, `manual_test()` or `show_settings()`.
`5` (or `q`, `done`, or end of input) leaves the menu. Any other input just
shows the menu again.

**Called by:** the main block when no known argument is given.

---

### Main block (`if __name__ == "__main__":`)

Reads the first command-line argument: `--data` → `run_datasets()`, `--test` →
`run_tests()` (exit code 0/1), `--manual` → `manual_test()`, anything else or
nothing → `menu()`. Ctrl+C ends the program cleanly.

---

## Functions in `make_samples.py`

Only needed to rebuild `data/W1_sample.csv` and `data/W2_sample.csv`.

| Function | What it does |
|---|---|
| `read_log(path)` | Reads the original log with `LOG_LINE`; keeps time, IP, User-Agent, path, `attack=0`; sorts by time. |
| `make_sessions(rows)` | Groups requests by (IP, User-Agent), starts a new session after a pause > 30 min (`IDLE_GAP`), keeps sessions with ≥ 7 requests (`MIN_REQUESTS`), sorts by start time, returns the first 100 (`N_SESSIONS`). |
| `network(ip)` | Returns the /16 part of an IP (first two numbers). |
| `add_attack(victim, attacker, kind)` | Adds a simulated hijack at the middle of the victim session. Attacker rows get the attacker's IP, the victim's or the attacker's User-Agent (for `copied_ua` types), and `attack=1`. *Concurrent*: inserts 2 attacker requests and the victim continues. *Takeover*: attacker replaces the second half. |
| `main()` | For W1 and W2: builds the sessions, adds an attack to every 5th session (the attacker is the next session from a different /16 network; the 4 types rotate), writes the CSV and prints how many sessions were written. |
