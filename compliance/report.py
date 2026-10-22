"""Risk assessment summary and report generation - Member 4."""
from datetime import datetime, timezone

SEVERITY_ORDER = ["informational", "low", "medium", "high"]
WEIGHTS = {"informational": 0, "low": 1, "medium": 3, "high": 5}


def summarize(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    overall = "none"
    for s in SEVERITY_ORDER:
        if counts[s] > 0:
            overall = s
    return {
        "total_findings": len(findings),
        "counts_by_severity": counts,
        "risk_score": sum(WEIGHTS[s] * n for s, n in counts.items()),
        "overall_risk": overall,
        "needs_manual_review": sum(
            1 for f in findings if f["confidence"] == "needs_manual_review"
        ),
    }


def generate_markdown(target, findings):
    s = summarize(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Security Assessment Report",
        "",
        f"- Target: {target}",
        f"- Generated: {now}",
        f"- Overall risk (highest severity observed): {s['overall_risk']}",
        f"- Risk score: {s['risk_score']}",
        f"- Total findings: {s['total_findings']} "
        f"({s['needs_manual_review']} need manual review)",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in reversed(SEVERITY_ORDER):
        lines.append(f"| {sev} | {s['counts_by_severity'][sev]} |")

    lines += ["", "## Detailed findings", ""]
    ordered = sorted(findings, key=lambda f: -SEVERITY_ORDER.index(f["severity"]))
    if not ordered:
        lines.append("No findings were produced from the observations provided.")
    for f in ordered:
        lines += [
            f"### {f['finding_id']}: {f['title']}",
            f"- Severity: {f['severity']}",
            f"- Confidence: {f['confidence']}",
            f"- Evidence: {f['evidence']}",
            f"- Recommendation: {f['recommendation']}",
        ]
        if f["compliance_references"]:
            lines.append("- Related controls:")
            for r in f["compliance_references"]:
                lines.append(
                    f"  - {r['framework']} {r['reference']} ({r['title']}) - "
                    f"mapping: {r['verification_status']}; "
                    f"reference verified: {r['source_verified']}. "
                    f"Rationale: {r['mapping_rationale']}"
                )
        lines.append("")

    lines += [
        "## Limitations",
        "",
        "- Findings are observations from a network scan, not confirmed vulnerabilities.",
        "- Control mappings show relevance only; this report is not a compliance "
        "certification or legal advice.",
        "- Only scan systems you are authorized to test. Unauthorized access may be "
        "an offence under Ethiopian law (for example the Computer Crime "
        "Proclamation No. 958/2016).",
        "",
    ]
    return "\n".join(lines)
