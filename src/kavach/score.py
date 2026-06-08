"""Threat-scoring helpers ported from @mukundakatta/kavach."""

from __future__ import annotations

import types
from dataclasses import dataclass, field
from typing import Iterable, List, Mapping, Optional, Union

# ---------------------------------------------------------------------------
# Catalogue (mirrors assets/threatScore.js -- weights kept identical).
# ---------------------------------------------------------------------------

SIGNALS: dict = {
    "promptInjection": {"weight": 0.35, "label": "Prompt-injection language detected"},
    "toolMisuse": {"weight": 0.30, "label": "Unusual tool / API call pattern"},
    "piiExfil": {"weight": 0.35, "label": "PII leaving the sandbox"},
    "credentialLeak": {"weight": 0.45, "label": "Credential-like string in output"},
    "jailbreakPattern": {"weight": 0.30, "label": "Known jailbreak template"},
    "rateAnomaly": {"weight": 0.15, "label": "Rate anomaly vs user baseline"},
    "geoAnomaly": {"weight": 0.15, "label": "New geography for this account"},
}

# Frozen view so consumers don't accidentally mutate the catalogue keys; values
# are still reachable via SIGNALS for tunability per deployment.
THREAT_MODELS: Mapping[str, Mapping[str, list]] = types.MappingProxyType(
    {
        "promptAbuse": {
            "surfaces": ["chat input", "tool arguments", "system prompts"],
            "controls": [
                "prompt injection detection",
                "tool scoping",
                "response review",
            ],
        },
        "dataExfiltration": {
            "surfaces": ["model output", "file export", "network egress"],
            "controls": ["DLP scanning", "egress allowlist", "secrets redaction"],
        },
        "accountTakeover": {
            "surfaces": ["auth session", "API token", "admin console"],
            "controls": ["re-auth", "geo anomaly alerts", "rate limiting"],
        },
    }
)


# Spec calls for ``score(signals: dict) -> ThreatScore``. We accept either a
# mapping (id -> truthy) or an iterable of ids for ergonomic Python use.
SignalInput = Union[Mapping[str, object], Iterable[str]]


@dataclass
class ThreatScore:
    """Bundled scoring result.

    Attributes:
        score: Float in ``[0, 1]``, rounded to 3 decimals.
        tier: ``"noise" | "low" | "medium" | "high" | "critical"``.
        contributors: Human-readable labels of every signal that fired.
        model: Inferred or pinned threat model name.
        playbook: Recommended controls (numbered/clean strings) for the model.
        action: Single-sentence SOC action recommendation for the tier.
    """

    score: float
    tier: str
    contributors: List[str] = field(default_factory=list)
    model: str = ""
    playbook: List[str] = field(default_factory=list)
    action: str = ""


# ---------------------------------------------------------------------------
# Lower-level helpers (1:1 with the JS sibling).
# ---------------------------------------------------------------------------


def _fired_ids(signals: SignalInput) -> List[str]:
    """Normalize the input into an ordered list of fired signal ids."""
    if isinstance(signals, Mapping):
        return [k for k, v in signals.items() if v]
    if isinstance(signals, str):
        # Be lenient -- `score("promptInjection")` shouldn't iterate chars.
        raise TypeError(
            "kavach: signals must be a dict (id -> truthy) or an iterable of ids"
        )
    try:
        return [str(s) for s in signals]
    except TypeError as e:
        raise TypeError(
            "kavach: signals must be a dict (id -> truthy) or an iterable of ids"
        ) from e


def threat_score(signals: SignalInput) -> dict:
    """Combine fired signals with diminishing returns.

    Mirrors the JS ``threatScore(firedSignals) -> { score, contributors }``.
    Returns a plain dict for parity; callers wanting the bundled tier +
    action should use :func:`triage` or :func:`score`.
    """
    fired = _fired_ids(signals)
    labels: List[str] = []
    acc = 1.0
    for sig_id in fired:
        sig = SIGNALS.get(sig_id)
        if sig is None:
            continue
        labels.append(sig["label"])
        weight = sig.get("weight", 0)
        acc *= 1.0 - max(0.0, min(1.0, float(weight)))
    return {"score": round(1.0 - acc, 3), "contributors": labels}


def tier_for(score_value: float) -> str:
    """Map a numeric score to a coarse tier label.

    Returns one of ``"critical" | "high" | "medium" | "low" | "noise"``.
    """
    s = float(score_value)
    if s >= 0.85:
        return "critical"
    if s >= 0.65:
        return "high"
    if s >= 0.35:
        return "medium"
    if s >= 0.15:
        return "low"
    return "noise"


def recommended_action(score_value: float) -> str:
    """Return the default SOC action for a numeric score."""
    return {
        "critical": "Terminate session and require re-auth.",
        "high": "Strip tool access and alert the on-call.",
        "medium": "Quarantine session to read-only sandbox.",
        "low": "Log and monitor.",
        "noise": "Ignore.",
    }[tier_for(score_value)]


def _infer_model(fired: List[str], context_model: Optional[str]) -> str:
    if context_model:
        return context_model
    if "piiExfil" in fired or "credentialLeak" in fired:
        return "dataExfiltration"
    if "geoAnomaly" in fired:
        return "accountTakeover"
    return "promptAbuse"


def triage(signals: SignalInput, *, model: Optional[str] = None) -> ThreatScore:
    """Bundled scoring -- mirrors the JS ``triageIncident`` shape."""
    fired = _fired_ids(signals)
    raw = threat_score(fired)
    inferred = _infer_model(fired, model)
    threat = THREAT_MODELS.get(inferred)
    playbook = list(threat["controls"]) if threat else []
    return ThreatScore(
        score=raw["score"],
        tier=tier_for(raw["score"]),
        contributors=list(raw["contributors"]),
        model=inferred,
        playbook=playbook,
        action=recommended_action(raw["score"]),
    )


def score(signals: SignalInput, *, model: Optional[str] = None) -> ThreatScore:
    """Public spec entrypoint: ``score(signals: dict) -> ThreatScore``.

    Accepts a dict mapping signal id to truthy, or any iterable of fired ids.
    Returns a :class:`ThreatScore` with ``score``, ``tier``, and ``playbook``.
    """
    return triage(signals, model=model)


def build_playbook(model: str) -> dict:
    """Return surfaces + numbered control steps for a threat model."""
    threat = THREAT_MODELS.get(model)
    if not threat:
        return {"model": model, "steps": [], "surfaces": []}
    return {
        "model": model,
        "surfaces": list(threat["surfaces"]),
        "steps": [f"{i + 1}. {ctrl}" for i, ctrl in enumerate(threat["controls"])],
    }
