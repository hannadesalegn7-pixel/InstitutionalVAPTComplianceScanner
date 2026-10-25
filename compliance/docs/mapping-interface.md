# Mapping interface (for the backend)

Script: `compliance/map_findings.py` (Python 3, standard library only).

Call it the same safe way as the scanner: pass arguments as a list, never build a shell string.
Example from Node: `spawn("python3", ["compliance/map_findings.py"])`, write the findings JSON to its stdin, read stdout.

## Input (stdin)
A JSON list of findings in the shared format:
`finding_id, title, target, port, protocol, service, version, severity, evidence, confidence, recommendation`
(`compliance_references` may be missing or empty).

## Output (stdout)
The SAME list. Only `compliance_references` is filled in. All other fields are returned unchanged.

Each reference:
```json
{
  "framework": "NIST SP 800-53 Rev 5",
  "reference": "AC-17",
  "title": "Remote Access",
  "rationale": "Telnet is a remote-access protocol; remote access should be controlled and protected.",
  "verification_status": "verified",
  "source_verified": true
}
```
- `verification_status`: `verified` or `needs_manual_review`
- `source_verified`: true when the control ID and title were confirmed in an official/public source
- A finding with no matching rule (or no port) gets `"compliance_references": []`

## Exit codes
- `0` success
- `1` bad input. stdout then contains `{"error": {"code": "INVALID_JSON" | "INVALID_INPUT", "message": "..."}}`

## Test it by hand
```
python3 compliance/map_findings.py < compliance/samples/sample-findings.json
```
