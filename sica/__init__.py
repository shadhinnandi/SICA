"""SICA: Session Integrity and Continuity Analysis.

Detector (what would run next to a web server):
    sessionize.py    parse an access log and rebuild sessions
    fingerprint.py   request -> client binding (address, /24, /16, browser, OS, device)
    invariants.py    V1 agent mutation, V2 scope discontinuity, V3 binding fork
    detector.py      per-session state, risk = sum w_i v_i, threshold, ALLOW / ALERT

Evaluation (how the reported results are produced):
    benchmark.py     benign mobility and simulated hijacks (levels L0-L5)
    evaluation.py    calibrate-then-evaluate protocol, metrics, baselines
    experiments.py   experiments E0-E7
    report.py        figures, summary, validation
"""
from .fingerprint import Binding, binding_of, ip_prefix24, ip_scope16, parse_user_agent
from .invariants import DEFAULT_INVARIANTS, INVARIANTS, InvariantParams
from .sessionize import Request, Session, load_sessions, parse_log, sessionize
from .detector import (ContinuityMonitor, MonitorConfig, SessionState, benign_rarity_weights,
                       calibrate, decision, threshold_for_budget)
from .benchmark import InjectionConfig, LEVELS, LEVELS_ALL, MODES, inject_session
from .evaluation import ExperimentConfig, run_baselines, run_experiment, split_sessions

__version__ = "2.0.0"
