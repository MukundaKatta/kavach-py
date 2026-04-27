"""kavach -- threat scoring for AI-app security monitoring.

Python port of @mukundakatta/kavach. Combines weighted detection signals with
diminishing returns so stacking many weak signals can't overrule a single
strong one.

Public surface:

    from kavach import (
        score,
        ThreatScore,
        SIGNALS,
        THREAT_MODELS,
        threat_score,
        tier_for,
        recommended_action,
        triage,
        build_playbook,
    )
"""

from .score import (
    SIGNALS,
    THREAT_MODELS,
    ThreatScore,
    build_playbook,
    recommended_action,
    score,
    threat_score,
    tier_for,
    triage,
)

__version__ = "0.1.0"
VERSION = __version__

__all__ = [
    "SIGNALS",
    "THREAT_MODELS",
    "VERSION",
    "ThreatScore",
    "build_playbook",
    "recommended_action",
    "score",
    "threat_score",
    "tier_for",
    "triage",
]
