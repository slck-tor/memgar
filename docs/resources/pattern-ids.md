# Pattern ID directory

Memgar pattern IDs use a category prefix + number scheme so SIEM events
back-link cleanly to the threat catalog.

## ID prefix map

| Prefix | Category | Severity range |
|---|---|---|
| `INJ-NNN` | Prompt injection / directive override | MEDIUM–HIGH |
| `EXFIL-NNN` | Data exfiltration / information leak | HIGH–CRITICAL |
| `EXEC-NNN` | Execution / malware / vulnerability exploit | HIGH–CRITICAL |
| `MANIP-NNN` | Manipulation / disinformation / bias injection | MEDIUM–HIGH |
| `CRED-NNN` | Credential leak / token disclosure | HIGH–CRITICAL |
| `PRIV-NNN` | Privilege escalation / admin claim | HIGH–CRITICAL |
| `FIN-NNN` | Financial fraud / wire transfer redirect | CRITICAL |
| `EVAS-NNN` | Encoding / obfuscation evasion | MEDIUM |
| `BHV-NNN` | Behavioural / sleeper / conditional trigger | MEDIUM–HIGH |
| `ML-DETECT-NNN` | Layer 2-ML transformer detection | severity from probability |

## ID lookup

The full catalog auto-generated from `memgar/patterns.py`:
[Threat catalog](../threats/catalog.md).

## SIEM mapping

OCSF events emitted by memgar include the pattern ID:

```json
{
  "memory": {
    "matched_threats": ["EXFIL-016", "INJ-001"],
    "mitre_attack":   ["T1213", "T1565"]
  }
}
```

Splunk / Sentinel / Elastic correlation rules can join on pattern ID for
prioritised alerting.

## Severity

```python
from memgar.models import Severity

Severity.LOW       # 1 — informational
Severity.MEDIUM    # 2 — risky but not blocking
Severity.HIGH      # 3 — likely attack
Severity.CRITICAL  # 4 — high confidence; always blocks
```

`risk_score` correlation:

| Severity | risk_score contribution |
|---|---|
| LOW | +10 |
| MEDIUM | +30 |
| HIGH | +60 |
| CRITICAL | +90 (always block) |

## Adding new patterns

See [Contributing](../development/contributing.md) for the workflow. The
short version:

1. Append a `Threat(...)` dataclass to `memgar/patterns.py`
2. Add positive examples to `ml/data/calibration_corpus.json`
3. Run the gold gate locally:
   ```bash
   python scripts/calibrate_fpfn.py \
       --corpus ml/data/calibration_corpus.json --no-llm
   python scripts/check_calibration_gate.py
   ```
4. Open a PR

After merge, regenerate the catalog page:

```bash
python scripts/build_threat_catalog.py
```
