"""Run SICA end to end.

    python run.py            main workflow: data -> sessions -> SICA -> evaluation -> results
    python run.py --all      the full study E0-E7 behind every paper table (about 1 hour)
    python run.py --report   rebuild paper tables, figures and summary from results/tables
    python run.py --test     unit and regression tests
    python run.py --dev      development studies on seeds 100-119 (not part of the results)

Everything is written to results/ (tables/, figures/, summary/) and paper/tables/.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from sica import experiments as E  # noqa: E402
from sica import report as R  # noqa: E402


def step(title: str) -> None:
    print(f"\n######## {title}", flush=True)


def run_tests() -> int:
    step("Tests")
    return subprocess.call([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(ROOT / "tests")],
                           cwd=ROOT)


def build_report() -> int:
    step("Report: paper tables, figures, summary, validation")
    R.make_tables()
    R.make_figures()
    status = R.validate()
    R.write_summary(validation_ok=(status == 0))
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="run every experiment E0-E7")
    mode.add_argument("--report", action="store_true", help="only rebuild the outputs")
    mode.add_argument("--test", action="store_true", help="only run the tests")
    mode.add_argument("--dev", action="store_true", help="development studies only")
    args = parser.parse_args()
    t0 = time.perf_counter()

    if args.test:
        return run_tests()
    if args.report:
        return build_report()
    if args.dev:
        E.run_dev_design()
        E.run_dev_invariants()
        return 0

    step("1. Load data and build sessions (E0)")
    E.run_e0()
    step("2-3. Run SICA and evaluate against the baselines (E1, E2)")
    E.run_e1()
    E.run_e1b()
    E.run_e2()
    E.run_decisions(seed=0)
    if args.all:
        step("Ablation (E3)")
        E.run_e3()
        step("Leakage audit (E5)")
        E.run_e5()
        step("Efficiency (E6)")
        E.run_e6()
        step("Robustness grid and sweeps (E4, about 43 minutes)")
        E.run_e4()
    else:
        print("\n(E3-E6 are not re-run; their stored tables in results/tables are used. "
              "Use --all to recompute them.)")
    step("Statistical tests (E7)")
    E.run_e7()
    status = build_report()
    print(f"\nFinished in {time.perf_counter() - t0:.0f} s. Results: results/summary/summary.md")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
