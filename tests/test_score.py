"""Tests for kavach.score."""

from __future__ import annotations

import pytest

from kavach import (
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


def test_score_with_dict_input_returns_threat_score_dataclass():
    r = score({"promptInjection": True, "toolMisuse": True})
    assert isinstance(r, ThreatScore)
    # Diminishing returns: 1 - (1-0.35)(1-0.30) = 1 - 0.455 = 0.545
    assert r.score == 0.545
    assert r.tier == "medium"
    assert "Prompt-injection language detected" in r.contributors
    assert "Unusual tool / API call pattern" in r.contributors


def test_score_accepts_iterable_of_ids():
    r = score(["promptInjection", "toolMisuse"])
    assert r.score == 0.545
    assert r.tier == "medium"


def test_score_dict_skips_falsy_signals():
    r = score(
        {
            "promptInjection": True,
            "toolMisuse": False,  # not fired
            "credentialLeak": 0,  # not fired
        }
    )
    assert r.score == 0.35
    assert "Unusual tool / API call pattern" not in r.contributors


def test_score_ignores_unknown_signal_ids():
    r = score(["promptInjection", "nonsenseSignal"])
    assert r.score == 0.35  # unknown id contributes nothing
    assert len(r.contributors) == 1


def test_score_no_signals_is_zero():
    r = score({})
    assert r.score == 0.0
    assert r.tier == "noise"
    assert r.contributors == []


def test_tier_thresholds():
    assert tier_for(0.0) == "noise"
    assert tier_for(0.14) == "noise"
    assert tier_for(0.15) == "low"
    assert tier_for(0.34) == "low"
    assert tier_for(0.35) == "medium"
    assert tier_for(0.64) == "medium"
    assert tier_for(0.65) == "high"
    assert tier_for(0.84) == "high"
    assert tier_for(0.85) == "critical"
    assert tier_for(1.0) == "critical"


def test_recommended_action_for_each_tier():
    assert recommended_action(0.95) == "Terminate session and require re-auth."
    assert recommended_action(0.7) == "Strip tool access and alert the on-call."
    assert recommended_action(0.4) == "Quarantine session to read-only sandbox."
    assert recommended_action(0.2) == "Log and monitor."
    assert recommended_action(0.0) == "Ignore."


def test_score_infers_data_exfiltration_model():
    r = score(["credentialLeak", "piiExfil"])
    assert r.model == "dataExfiltration"
    assert r.playbook == ["DLP scanning", "egress allowlist", "secrets redaction"]


def test_score_infers_account_takeover_model_from_geo_anomaly():
    r = score(["geoAnomaly"])
    assert r.model == "accountTakeover"


def test_score_defaults_to_prompt_abuse_model():
    r = score(["promptInjection"])
    assert r.model == "promptAbuse"


def test_explicit_model_overrides_inference():
    r = score(["credentialLeak"], model="promptAbuse")
    assert r.model == "promptAbuse"
    assert r.playbook == THREAT_MODELS["promptAbuse"]["controls"]


def test_score_high_severity_yields_high_action():
    r = score(["credentialLeak", "piiExfil", "promptInjection"])
    # 1 - (1-0.45)(1-0.35)(1-0.35) = 1 - 0.55*0.65*0.65 = 1 - 0.232... = 0.768
    assert r.score >= 0.65
    assert r.tier == "high"


def test_threat_score_returns_dict_for_parity():
    raw = threat_score(["promptInjection"])
    assert raw == {
        "score": 0.35,
        "contributors": ["Prompt-injection language detected"],
    }


def test_triage_alias_returns_threat_score():
    r = triage(["promptInjection"])
    assert isinstance(r, ThreatScore)
    assert r.score == 0.35


def test_build_playbook_returns_numbered_steps():
    pb = build_playbook("promptAbuse")
    assert pb["model"] == "promptAbuse"
    assert pb["steps"] == [
        "1. prompt injection detection",
        "2. tool scoping",
        "3. response review",
    ]
    assert pb["surfaces"] == ["chat input", "tool arguments", "system prompts"]


def test_build_playbook_unknown_model_returns_empty():
    pb = build_playbook("notARealModel")
    assert pb == {"model": "notARealModel", "steps": [], "surfaces": []}


def test_score_rejects_string_input_to_avoid_iterating_chars():
    with pytest.raises(TypeError):
        score("promptInjection")  # type: ignore[arg-type]


def test_signals_catalogue_exposes_known_ids():
    assert "promptInjection" in SIGNALS
    assert "credentialLeak" in SIGNALS
    assert SIGNALS["promptInjection"]["weight"] == 0.35
