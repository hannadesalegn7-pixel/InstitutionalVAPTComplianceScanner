# Security Assessment Report

- Target: 192.168.1.10
- Generated: 2026-10-25 11:53 UTC
- Overall risk (highest severity observed): high
- Risk score: 6
- Total findings: 5 (2 need manual review)

## Findings by severity

| Severity | Count |
|---|---|
| high | 1 |
| medium | 0 |
| low | 1 |
| informational | 3 |

## Detailed findings

### finding-003: Telnet service exposed
- Severity: high
- Confidence: observed
- Evidence: telnet observed on port 23/tcp
- Recommendation: Disable Telnet and use SSH with key-based authentication.
- Related controls:
  - NIST SP 800-53 Rev 5 AC-17 (Remote Access) - mapping: verified; reference verified: True. Rationale: Telnet is a remote-access protocol; remote access should be controlled and protected.
  - NIST SP 800-53 Rev 5 SC-8 (Transmission Confidentiality and Integrity) - mapping: needs_manual_review; reference verified: True. Rationale: Telnet does not protect data in transit.
  - Ethiopia - Personal Data Protection Proclamation No. 1321/2024 Security measures provisions (exact article to be confirmed) (Technical and organisational measures for personal data security) - mapping: needs_manual_review; reference verified: False. Rationale: May be relevant to personal-data security measures if personal data is processed on this system; cannot be concluded from a scan alone.

### finding-004: HTTP service without observed HTTPS
- Severity: low
- Confidence: observed
- Evidence: http observed on port 80/tcp
- Recommendation: Verify whether HTTP is required; redirect to HTTPS where possible.
- Related controls:
  - NIST SP 800-53 Rev 5 SC-8 (Transmission Confidentiality and Integrity) - mapping: needs_manual_review; reference verified: True. Rationale: HTTP does not protect data in transit.
  - Ethiopia - Personal Data Protection Proclamation No. 1321/2024 Security measures provisions (exact article to be confirmed) (Technical and organisational measures for personal data security) - mapping: needs_manual_review; reference verified: False. Rationale: May be relevant to personal-data security measures if personal data is processed on this system; cannot be concluded from a scan alone.

### finding-001: SSH service detected
- Severity: informational
- Confidence: observed
- Evidence: ssh observed on port 22/tcp (version: OpenSSH 8.9)
- Recommendation: Confirm SSH is required and limit access to authorized users.
- Related controls:
  - NIST SP 800-53 Rev 5 AC-17 (Remote Access) - mapping: verified; reference verified: True. Rationale: SSH is a remote-access service whose use should be authorized.

### finding-002: Service version banner detected
- Severity: informational
- Confidence: needs_manual_review
- Evidence: ssh observed on port 22/tcp (version: OpenSSH 8.9)
- Recommendation: Compare the version with vendor advisories and confirm patch level manually.

### finding-005: Service on unexpected port
- Severity: informational
- Confidence: needs_manual_review
- Evidence: http observed on port 8888/tcp
- Recommendation: Confirm with the system owner that this service and port are intended.
- Related controls:
  - NIST SP 800-53 Rev 5 CM-7 (Least Functionality) - mapping: needs_manual_review; reference verified: True. Rationale: Unexpected service placement may indicate a service that is not intended.

## Limitations

- Findings are observations from a network scan, not confirmed vulnerabilities.
- Control mappings show relevance only; this report is not a compliance certification or legal advice.
- Only scan systems you are authorized to test. Unauthorized access may be an offence under Ethiopian law (for example the Computer Crime Proclamation No. 958/2016).
