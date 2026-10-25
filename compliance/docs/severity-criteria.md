# Severity Criteria

| Severity | Meaning |
|---|---|
| high | Legacy cleartext remote-access service exposed |
| medium | Sensitive service reachable that may need restriction |
| low | Service that may be unnecessary or unencrypted; review needed |
| informational | Observation only; no direct concern |

## Confidence values
- observed: seen directly in scanner output
- needs_manual_review: cannot be concluded from the scan alone
- verified: confirmed with additional evidence

## Risk score
Each finding adds points: informational 0, low 1, medium 3, high 5.
Overall risk = the highest severity observed.
