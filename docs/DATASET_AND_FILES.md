# Datasets and Project Files

This guide explains the data SICA uses, what every column in the logs means and
how it is used, and what every file in the project does.

---

## Part 1: The Datasets

### What type of data is it?

SICA uses **web server access logs**. These are plain-text files that a web
server (Apache or Nginx) writes automatically: one line per HTTP request. Both
files use the standard **NCSA combined log format**.

The logs are **unlabelled**. Nothing in them says "this session was hijacked".
That is normal, because no public dataset of labelled HTTP session hijacks
exists. The project therefore builds its own test cases on top of the real
traffic (see [How the benchmark is built](#how-the-benchmark-is-built)).

### The two datasets

| | W1 | W2 |
|---|---|---|
| File | `data/W1/apache_sample_1.log` | `data/W2/nginx_real.log` |
| Server | Apache | Nginx |
| Source | Elastic Examples, `apache_logs` | Elastic Examples, `nginx_logs` |
| Traffic | a personal technical website: human browsing, feed readers, crawlers | demo log, almost all Debian/Ubuntu package clients (APT) |
| Requests | 10,000 | 51,462 |
| Distinct IP addresses | 1,753 | 2,660 |
| Distinct User-Agent strings | 558 | 136 |
| Requests with a referrer | 59.3% | 0.03% |
| Sessions (7 or more requests) | 254 | 3,126 |
| Calibration + evaluation sessions | 127 + 127 | 1,563 + 1,563 |

Both files come from https://github.com/elastic/examples under the Apache 2.0
licence (`data/LICENSE-APACHE-2.0.txt`). Only the file names were changed.

**Why two datasets?** W1 is realistic, varied browsing with many different
browsers, which suits V1 well. W2 is a harder case: almost every client is the
same package manager, so V1 has little to work with, and it has almost no
referrers. Testing on both shows how SICA behaves on easy and hard traffic.

### One line, column by column

A real line from W1:

```
83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
```

A real line from W2:

```
93.180.71.3 - - [17/May/2015:08:05:32 +0000] "GET /downloads/product_1 HTTP/1.1" 304 0 "-" "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.21)"
```

| # | Column | Example | What it means | How SICA uses it |
|---|---|---|---|---|
| 1 | **Client IP address** | `83.149.9.216` | the address the request came from | **Core signal.** Becomes the network part of the binding: exact IP, /24 (`83.149.9`) and /16 (`83.149`). Used by V2 and V3. Also half of the session grouping key. |
| 2 | Ident | `-` | old identity protocol field | Always empty. Ignored. |
| 3 | User | `-` | HTTP login name | Always empty. Ignored. |
| 4 | **Timestamp** | `[17/May/2015:10:05:03 +0000]` | when the request arrived | Puts requests in order, starts a new session after 30 minutes idle, and splits sessions into an earlier calibration half and a later evaluation half. V1 to V3 do not use time. |
| 5 | Request line | `GET /presentations/... HTTP/1.1` | method, path and protocol | Only the path is kept. Not used by the detector. Travels with the real attacker requests and is used in the leakage audit (distinct paths). |
| 6 | Status code | `200`, `304` | server response code | Not used by the detector. Used in the leakage audit (error rate). |
| 7 | Response size | `203023` | bytes sent back (`-` becomes 0) | Not used by the detector. Used in the leakage audit (bytes per session). |
| 8 | Referrer | `"http://semicomplete.com/..."` | the page that linked to this request | Used only by the rejected V6 navigation rule. W2 has almost none, so V6 is switched off there automatically. |
| 9 | **User-Agent** | `"Mozilla/5.0 ... Chrome/32.0..."` | the browser's description of itself | **Core signal.** Parsed into browser, major version, operating system and device class: the agent part of the binding. Used by V1 and V3. Also the other half of the session grouping key. |

**In short:** detection uses only two columns, **IP address and User-Agent**.
The timestamp only orders and splits sessions. The other columns are used to
check that the benchmark is fair, never to make a decision.

### From a line to a client binding

The IP address and User-Agent of each request become a seven-field binding:

```
IP 83.149.9.216 | /24 83.149.9 | /16 83.149 | Chrome | 32 | macOS | Desktop
\______________ network part ____________/   \________ agent part ________/
```

### How sessions are rebuilt

Access logs do not store cookies, so sessions are rebuilt from the log:

1. Sort all requests by time.
2. Group requests with the same **(IP address, User-Agent)**.
3. Start a new session when there is a gap of more than **30 minutes**.
4. Keep sessions with at least **7 requests**, so each one has room for an attack.
5. Split sessions by start time: the earlier half for **calibration**, the later
   half for **evaluation**.

### How the benchmark is built

Grouping by (IP, User-Agent) makes every real session look perfectly stable, so
two things are added.

**1. Legitimate mobility** (both halves), so SICA must tolerate honest changes:

| Type | What happens | Share of benign sessions |
|---|---|---|
| M1 handover | the IP changes once and stays changed | 15% in total for M1 to M3 |
| M2 agent update | the browser version changes once | (chosen evenly) |
| M3 combined | both at the same moment | |
| M4 flapping | the IP keeps switching between two networks | 5% |

A new IP lands in the same /24 (50%), another /24 of the same /16 (30%) or
another /16 (20%).

**2. Hijacks** (evaluation half only; calibration stays attack-free):

- Each evaluation session becomes a victim with probability 0.2.
- The attack starts at a point between 25% and 50% of the session.
- The attacker's requests are **real requests from another client** of the same
  server; only the IP and User-Agent are set according to the attacker level.
- Sessions keep their original length, so length reveals nothing.

| Level | Attacker IP | Attacker User-Agent |
|---|---|---|
| L0 | different /16 | own |
| L1 | different /16 | copied from the victim |
| L2 | same /16, different /24 | own |
| L3 | same /24, different host | copied from the victim |
| L4 | victim's exact IP | copied from the victim (identical binding) |
| L5 | victim's exact IP | own |

Each level runs in two modes: **takeover** (the victim stops) and **concurrent**
(the victim keeps browsing).

### Known data limitations

- The **minute field** in both logs is broken (almost always `05`), so no session
  is longer than 59 seconds. The project makes no timing claims.
- W2 is demo data with only three URLs, and 65.8% of its responses are 404.
- The attacks and the mobility are simulated on real traffic, not captured from
  real incidents.

---

## Part 2: Every File Explained

### Top level

| File | Purpose |
|---|---|
| `run.py` | The single entry point. Parses the command-line option (`--all`, `--report`, `--test`, `--dev`) and calls the experiments and the report in the right order. |
| `requirements.txt` | Python packages: numpy, pandas, scipy, matplotlib, pytest. |
| `README.md` | Short project overview and how to run it. |
| `testing.md` | The whole project explained in simple language. |
| `LICENSE` | MIT licence for the code and results. |
| `.gitignore` | Tells git to skip caches and LaTeX build files. |
| `.gitattributes` | Keeps the log files byte-exact and marks generated files for GitHub. |

### `sica/`: the Python package

The first four files are the **detector** (what would run next to a real
server). The other four **evaluate** it.

| File | Role | How it works |
|---|---|---|
| `__init__.py` | Package overview | Lists the modules and exports the main classes and functions. |
| `sessionize.py` | Detector: input | `parse_log` reads each combined-format line with a regular expression into a table (IP, time, path, status, bytes, referrer, User-Agent) and skips broken lines. `sessionize` groups by (IP, User-Agent), cuts at 30-minute gaps and drops sessions under 7 requests. |
| `fingerprint.py` | Detector: binding | `binding_of(ip, user_agent)` builds the seven-field `Binding`. `ip_prefix24` and `ip_scope16` cut the address; `parse_user_agent` finds the browser, major version, OS and device with fixed keyword rules. A missing User-Agent becomes "unknown". |
| `invariants.py` | Detector: checks | `v1_agent_mutation` (1.00 / 0.35 / 0), `v2_scope_discontinuity` (1.00 / 0.45 / 0.15 / 0) and `v3_binding_fork` (1.00 on a revisit). Also holds V4 to V6, which were rejected and are kept only for the ablation study. All constants live in `InvariantParams`. |
| `detector.py` | Detector: risk and decision | `ContinuityMonitor.observe` handles one request: builds the binding, runs V1 to V3, computes `R = sum(w_i * V_i)`, updates the session peak and the state (reference binding, previous key, 4-entry ring). `calibrate` computes the weights from benign rarity and `threshold_for_budget` picks the threshold for the alert budget. `decision` returns ALLOW or ALERT. |
| `benchmark.py` | Evaluation: test cases | `apply_churn` adds legitimate mobility (M1 to M4). `inject_session` turns a session into a hijack at a chosen level (L0 to L5) and mode using real donor requests. |
| `evaluation.py` | Evaluation: one run | `run_experiment` does one full calibrate-then-evaluate run: split, add mobility, inject attacks, calibrate, replay, then compute metrics (`confusion`, `rate_metrics`, `roc_auc`, `pr_auc`, `bootstrap_ci`). Also contains the pinning and scored baselines. |
| `experiments.py` | Evaluation: the study | One function per experiment (`run_e0` to `run_e7`, plus development studies). Each runs many seeds and writes CSV tables to `results/tables/`. |
| `report.py` | Evaluation: outputs | `make_figures` draws the six figures, `write_summary` writes `summary.md`, and `validate` runs 56 integrity checks on the finished results. |

### `data/`

| File | Purpose |
|---|---|
| `W1/apache_sample_1.log` | Dataset W1 (Apache, 10,000 requests). |
| `W2/nginx_real.log` | Dataset W2 (Nginx, 51,462 requests). |
| `LICENSE-APACHE-2.0.txt` | Licence of the two logs. |

### `results/`

| Folder or file | Purpose |
|---|---|
| `tables/*.csv` | Every result, named by experiment: `e0_` corpus statistics, `e1_` main result and calibration, `e2_` baselines, `e3_` ablation, `e4_` attacker levels and sweeps, `e5_` leakage audit, `e6_` speed and memory, `e7_` statistical tests and base rates. Files ending in `_runs` hold one row per seed; the others hold averages. |
| `figures/fig1` to `fig6` | Architecture, binding-fork mechanism, recall per attacker level, budget sweep against pinning, mobility crossover, ablation (PDF and PNG). |
| `summary/summary.md` | One-page summary of the final numbers. |
| `summary/decisions_seed0.csv` | The ALLOW/ALERT decision, peak risk and explanation for every session of seed 0. |
| `summary/leakage_report.json` | Results of the 26 structural checks of the benchmark. |
| `summary/e6_environment.json` | Machine and Python version used for the timing experiment. |
| `summary/e0_sessionisation.json` | Settings used to rebuild sessions. |

### `tests/`

| File | Purpose |
|---|---|
| `conftest.py` | Makes the `sica` package importable for pytest. |
| `test_sica.py` | Unit and protocol tests: IP prefixes, User-Agent parsing, each check, state updates, weights, threshold, attack injection, calibration and reproducibility. |
| `test_regressions.py` | Tests that lock in bugs fixed during development so they cannot come back. |

Together they run 50 tests (`python run.py --test`).

### `paper/`: the course report

| File | Purpose |
|---|---|
| `report.tex` | Source of the four-page IEEE-style course report. |
| `report.bib` | The 10 references cited in the report. |
| `report.pdf` | The compiled report. |
| `IEEEtran.cls` | IEEE page layout (two columns, fonts, headings). |
| `IEEEtran.bst` | IEEE reference formatting for BibTeX. |
| `figures/report_architecture.tex` | The architecture figure, drawn with TikZ. |
| `figures/roc.pdf` | The ROC result plot used in the report. |

### `docs/`

| File | Purpose |
|---|---|
| `DATASET_AND_FILES.md` | This guide. |
| `WORKED_EXAMPLE.md` | Hand calculation of a legitimate user and a caught attacker. |
