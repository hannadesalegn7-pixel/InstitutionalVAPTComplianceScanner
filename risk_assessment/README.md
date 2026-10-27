# Risk Assessment

## Status

This folder is a placeholder from the original team structure (Member 4:
"Risk Assessment, Compliance & Reporting"). No separate implementation
lives here — all risk classification, severity scoring, and mitigation
logic were built directly inside `compliance/` instead, alongside the
compliance mapping engine they depend on.

See `compliance/rules_engine.py` and `compliance/docs/severity-criteria.md`
for the actual implementation.

## What risk assessment means in this project

Every finding produced by the scanner is assigned a **severity** and a
**confidence** level by the rules in `compliance/rules/rules.json`. These
two values together form the risk assessment for that finding — there is
no separate scoring step or model; severity is assigned directly by the
rule that matched.

### Severity levels

| Severity | Meaning |
|---|---|
| high | Legacy cleartext remote-access service exposed |
| medium | Sensitive service reachable that may need restriction |
| low | Service that may be unnecessary or unencrypted; review needed |
| informational | Observation only; no direct concern |

### Confidence levels

| Confidence | Meaning |
|---|---|
| observed | Seen directly in scanner output |
| needs_manual_review | Cannot be concluded from the scan alone |
| verified | Confirmed with additional evidence |

### Risk scoring

Each finding contributes points based on severity:

| Severity | Points |
|---|---|
| informational | 0 |
| low | 1 |
| medium | 3 |
| high | 5 |

A scan's **overall risk** is the highest severity observed across all its
findings (not the sum of points). The point total is reported alongside
it as a secondary risk score — see `compliance/docs/sample-report.md` for
an example of both values in a finished report.

## Mitigation recommendations

Each rule in `compliance/rules/rules.json` carries a `recommendation`
field with specific remediation guidance (e.g. "Disable Telnet and use
SSH with key-based authentication"). This is attached to every finding
automatically when the rule fires — there is no separate recommendation
engine.

## Compliance mappings

Risk is also expressed through relevance to external security controls
(NIST SP 800-53, CIS Controls v8, and one Ethiopian data-protection
reference still pending verification). This mapping is handled entirely
by `compliance/rules_engine.py` and documented in
`compliance/docs/mapping-interface.md` and
`compliance/docs/reference-verification.md`.

## Important limitation

A severity or risk score here reflects what a **basic TCP/service scan**
can observe — not a confirmed vulnerability, and not a legal compliance
judgment. See `compliance/docs/limitations.md` for the full list of what
these findings can and cannot prove.
