"""SmartWatch: measure how densely the agents of a multi-agent system talk to each other, window by
window; raise a graded alert as coordination intensifies; and, when it stays at the reset level, propose
(or issue) a reset of the agents involved before the coordination outgrows what a human can follow.
"""
from ._version import __version__
from .audit import AuditLog, verify_file
from .calibrate import calibrated_policy, thresholds
from .client import Client, CommandPoller, Reporter
from .engine import Engine, EventError, density_micro
from .policy import DEFAULT_POLICY, Policy, PolicyError
from .service import Watcher

__all__ = ['__version__', 'AuditLog', 'Client', 'CommandPoller', 'DEFAULT_POLICY', 'Engine', 'EventError', 'Policy',
           'PolicyError', 'Reporter', 'Watcher', 'calibrated_policy', 'density_micro', 'thresholds', 'verify_file']
