#!/usr/bin/env bash
#
# Reproduce every reported result, table and figure from the raw access logs.
#
# Failures are fatal and loud: a stage that exits non-zero stops the run, and no
# completion marker is written. The marker file results/PIPELINE_DONE is the
# only evidence that a run finished, so a partial run cannot be mistaken for a
# complete one.
#
# Usage:
#   ./run_all.sh              full run (~45 min on one core)
#   ./run_all.sh --quick      smoke test: fewer seeds, no robustness grid
#   ./run_all.sh --dev        additionally re-run the two development studies

set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
mkdir -p results/logs results/tables results/figures results/metadata paper/tables

QUICK=0
DEV=0
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --dev)   DEV=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

rm -f results/PIPELINE_DONE results/PIPELINE_ERR

fail() {
    echo "" >&2
    echo "FAILED at stage: $1" >&2
    echo "see results/logs/$1.log" >&2
    echo "$1" > results/PIPELINE_ERR
    exit 1
}

stage() {
    local name="$1"; shift
    echo "=== $name"
    if ! "$@" 2>&1 | tee "results/logs/${name}.log"; then
        fail "$name"
    fi
    # tee masks the exit status; PIPESTATUS is checked explicitly.
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        fail "$name"
    fi
}

# --- 0. environment and inputs -------------------------------------------
echo "=== preflight"
python3 - <<'PY' || { echo "preflight failed" >&2; exit 1; }
import sys
from pathlib import Path
assert sys.version_info >= (3, 10), f"Python 3.10+ required, found {sys.version.split()[0]}"
for module in ("numpy", "pandas", "scipy", "matplotlib"):
    __import__(module)
missing = [p for p in ("data/raw/apache_sample_1.log", "data/raw/nginx_real.log")
           if not Path(p).is_file()]
if missing:
    raise SystemExit(
        "Missing input logs: " + ", ".join(missing) + "\n"
        "These are the two real access logs the study runs on. See DATASET.md "
        "section 'Obtaining the logs' for their provenance and how to restore them.")
print(f"  python {sys.version.split()[0]}; inputs present")
PY

# --- 1. tests before results ---------------------------------------------
stage tests python3 -m pytest -q

# --- 2. experiments -------------------------------------------------------
stage exp01_corpus     python3 pipeline/exp01_corpus.py
stage exp02_main       python3 pipeline/exp02_main.py
stage exp03_ablation   python3 pipeline/exp03_ablation.py
stage exp05_leakage    python3 pipeline/exp05_leakage.py
stage exp06_efficiency python3 pipeline/exp06_efficiency.py
if [ "$QUICK" -eq 0 ]; then
    stage exp04_robustness python3 pipeline/exp04_robustness.py
else
    echo "=== exp04_robustness  (skipped: --quick)"
fi
stage exp07_stats      python3 pipeline/exp07_stats.py

if [ "$DEV" -eq 1 ]; then
    stage dev_design     python3 pipeline/dev_design.py
    stage dev_invariants python3 pipeline/dev_invariants.py
fi

# --- 3. tables and figures ------------------------------------------------
stage make_tables python3 pipeline/make_tables.py
stage figures     python3 pipeline/exp08_figures.py

# --- 4. validation --------------------------------------------------------
stage validate python3 pipeline/validate.py

echo "DONE $(date -u +%Y-%m-%dT%H:%M:%SZ)" > results/PIPELINE_DONE
echo ""
echo "=== all stages complete; marker written to results/PIPELINE_DONE"
