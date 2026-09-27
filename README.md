# SICA: Session Integrity and Continuity Analysis

SICA is a lightweight, rule-based detector for **mid-session HTTP session
hijacking**. It works from the access logs a web server already writes. For
every request it builds a *client binding* (IP address, /24 and /16 network,
browser, version, operating system and device), checks how that binding changes
during the session, and turns the changes into a risk score. A threshold
calibrated on attack-free traffic then decides **ALLOW** or **ALERT**, and every
alert explains which checks caused it.

The key idea is the **binding fork**. A legitimate user who changes network moves
one way (`A A A B B B`). When an attacker uses a stolen session while the victim
is still active, the two clients alternate and an earlier binding comes back
(`A A B A B`). SICA detects that return.

---

## Highlights

- **Server-log only.** Needs just the IP address and User-Agent from standard
  Apache/Nginx logs. No client changes, JavaScript or extra data collection.
- **No machine learning.** Three fixed checks, three weights and one threshold.
  The same input always gives the same output.
- **Controlled false alarms.** The threshold is chosen from benign sessions for a
  1% alert budget that the operator can change.
- **Explainable.** Every alert names the checks that fired, for example
  `V2_scope_discontinuity=1.00|V3_binding_fork=1.00`.
- **Fast.** Constant work per request, about 55,000 requests per second in
  Python and a few kilobytes of state per live session.

## How It Works

```
Access log -> Sessions -> Client binding -> V1 / V2 / V3 -> Risk score -> Threshold -> ALLOW / ALERT
```

| Check | What it looks for | Value |
|---|---|---|
| V1 Agent mutation | browser, OS or device changed / only the version changed | 1.00 / 0.35 |
| V2 Network discontinuity | new /16 / new /24 / new host in the same /24 | 1.00 / 0.45 / 0.15 |
| V3 Binding fork | an earlier binding returns after a different one | 1.00 |

Risk per request is `R = w1*V1 + w2*V2 + w3*V3`. The weights come from how rare
each check is on benign traffic, and a session alerts when its peak risk reaches
the calibrated threshold.

## Results

Two public access-log datasets with injected hijacks and simulated legitimate
mobility, 1% alert budget, mean of 30 seeds:

| Dataset | ROC AUC | Recall | FPR | Precision | PR AUC |
|---|---|---|---|---|---|
| W1 (Apache, human web browsing) | 0.884 | 0.358 | 0.85% | 0.906 | 0.742 |
| W2 (Nginx, package clients) | 0.851 | 0.229 | 0.56% | 0.920 | 0.667 |

SICA keeps false alarms below 1% with more than 9 of 10 alerts being real
hijacks, while IP pinning alarms on about 15% of benign sessions. It is strongest
against concurrent use of a session from a different network or client. Its
scope is what an access log can show: attackers who copy the victim's exact
binding, and most silent takeovers, stay outside what these fields reveal.

## Getting Started

**Requirements:** Python 3.10 or newer.

```bash
pip install -r requirements.txt
```

## Running the Project

| Command | What it does | Time |
|---|---|---|
| `python run.py` | Main workflow: data, sessions, SICA, evaluation (E0, E1, E2, E7), figures, summary and validation | about 6 min |
| `python run.py --all` | Full study: every experiment E0 to E7, then figures, summary and validation | about 1 hour |
| `python run.py --report` | Rebuild figures and summary from the stored result tables, then validate | seconds |
| `python run.py --test` | Run the 50 unit and regression tests | under 1 min |
| `python run.py --dev` | Development studies on seeds 100 to 119 (not part of the reported results) | 10 to 20 min |

**Run the full project from scratch:**

```bash
pip install -r requirements.txt
python run.py --test      # 1. check the code (50 tests)
python run.py --all       # 2. run every experiment and rebuild all outputs
cat results/summary/summary.md   # 3. read the final results
```

Every result is deterministic given the seeds. Only the E6 timing numbers change
with the machine.

**Build the course report** (pdfLaTeX and BibTeX):

```bash
cd paper
pdflatex report && bibtex report && pdflatex report && pdflatex report
```

## Outputs

| Output | Location |
|---|---|
| Result tables (CSV, `e0_` to `e7_`) | `results/tables/` |
| Figures (PDF and PNG) | `results/figures/` |
| One-page results summary | `results/summary/summary.md` |
| Per-session decisions for seed 0 | `results/summary/decisions_seed0.csv` |
| Course report | `paper/report.pdf` |

The validation step checks the finished result set (56 checks, for example that
every run meets its budget on calibration and that the detector imports no
machine-learning library).

## Project Structure

```
sica/
├── run.py              single entry point
├── requirements.txt    Python dependencies
├── testing.md          full project guide in simple language
├── docs/               dataset and file guide, hand-calculation example
├── sica/               Python package (detector and evaluation)
├── data/               W1 and W2 access logs (Apache 2.0)
├── results/            tables, figures and summary
├── tests/              unit and regression tests
└── paper/              four-page course report (LaTeX and PDF)
```

## Documentation

- [`testing.md`](testing.md): the whole project explained simply, including
  workflow, architecture, calculations, results and how it is tested.
- [`docs/DATASET_AND_FILES.md`](docs/DATASET_AND_FILES.md): the datasets, every
  log column, and the purpose of every file in the project.
- [`docs/WORKED_EXAMPLE.md`](docs/WORKED_EXAMPLE.md): a step-by-step hand
  calculation of a legitimate user and a caught attacker.
- [`paper/report.pdf`](paper/report.pdf): the four-page course report.

## Data and License

The datasets are public sample logs from the
[Elastic Examples](https://github.com/elastic/examples) repository, licensed
under Apache 2.0 (`data/LICENSE-APACHE-2.0.txt`). The code and results are
released under the MIT License (`LICENSE`).
