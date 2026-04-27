# kavach-py

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

*कवच -- shield, armour.*

**A small, inspectable threat-scoring library for AI-app security monitoring.** Zero runtime dependencies.

Python port of [@mukundakatta/kavach](https://github.com/MukundaKatta/kavach). Combines weighted detection signals with diminishing returns so stacking many weak signals can't overrule a single strong one. Returns a bounded score, a tier, a contributor list, and a recommended SOC playbook.

## Install

```bash
pip install kavach-py
```

## Usage

```python
from kavach import score

result = score({
    "promptInjection": True,
    "toolMisuse": True,
    "credentialLeak": False,
})

result.score        # 0.545  -- bounded [0, 1]
result.tier         # "medium"  -- one of "low" | "medium" | "high" | "critical" (or "noise" below 0.15)
result.contributors # ["Prompt-injection language detected", "Unusual tool / API call pattern"]
result.playbook     # ["DLP scanning", "egress allowlist", ...]
result.action       # "Quarantine session to read-only sandbox."
```

You can pass any of:

* a dict mapping **signal id -> truthy** (matches the spec's `signals: dict`),
* a list/tuple/set of fired signal ids.

```python
score(["promptInjection", "toolMisuse"])  # same result as the dict above
```

Use `triage(signals, model=...)` if you want to pin the threat model rather
than letting kavach infer it from the signals.

## Signals

| Signal | Weight | What fires it |
|---|---|---|
| `promptInjection` | 0.35 | Prompt-injection language patterns in user input |
| `toolMisuse` | 0.30 | Unusual tool / API call pattern vs baseline |
| `piiExfil` | 0.35 | PII detected in model output or egress |
| `credentialLeak` | 0.45 | Credential-like string in model output |
| `jailbreakPattern` | 0.30 | Known jailbreak template match |
| `rateAnomaly` | 0.15 | Rate anomaly vs user baseline |
| `geoAnomaly` | 0.15 | New geography for this account |

The `SIGNALS` dict is exported and mutable per-deployment.

## Tiers

| Score range | Tier | Recommended action |
|---|---|---|
| `>= 0.85` | `critical` | Terminate session and require re-auth. |
| `>= 0.65` | `high` | Strip tool access and alert the on-call. |
| `>= 0.35` | `medium` | Quarantine session to read-only sandbox. |
| `>= 0.15` | `low` | Log and monitor. |
| else | `noise` | Ignore. |

## Threat models + playbooks

Three coarse classes of AI-app attack:

* `promptAbuse` -- chat input, tool arguments, system prompts.
* `dataExfiltration` -- model output, file export, network egress.
* `accountTakeover` -- auth session, API token, admin console.

`build_playbook(model)` returns the surfaces and numbered control steps for a
given model.

## API differences from the JS sibling

* `score(signals)` accepts a dict or iterable of fired ids -- closer to the
  Python `signals: dict -> ThreatScore` spec.
* Returns a `ThreatScore` dataclass (`score`, `tier`, `contributors`, `model`,
  `playbook`, `action`) instead of separate `threatScore` + `tier` +
  `triageIncident` calls.
* Lower-level helpers `threat_score`, `tier_for`, `recommended_action`,
  `triage`, `build_playbook` are all available for parity.

See the JS sibling's [README](https://github.com/MukundaKatta/kavach) for
broader context.
