"""Session-continuity monitoring for post-authentication session-hijack detection."""
from .fingerprint import Binding, binding_of, ip_prefix24, ip_scope16, parse_user_agent
from .invariants import DEFAULT_INVARIANTS, INVARIANTS, InvariantParams
from .monitor import ContinuityMonitor, MonitorConfig, SessionState
from .calibrate import calibrate, benign_rarity_weights, threshold_for_budget
from .sessionize import Request, Session, load_sessions, parse_log, sessionize
from .inject import InjectionConfig, LEVELS, LEVELS_ALL, MODES, inject_session
from .harness import ExperimentConfig, run_experiment, run_baselines, split_sessions
from . import metrics, baselines

__version__ = "2.0.0"
