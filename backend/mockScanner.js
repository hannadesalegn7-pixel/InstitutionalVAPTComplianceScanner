function runMockScan(target) {
    return [
        {
            finding_id: "finding-001",
            title: "HTTP service detected",
            target,
            port: 80,
            protocol: "tcp",
            service: "http",
            severity: "informational",
            evidence: "HTTP service observed on port 80",
            confidence: "observed",
            recommendation: "Verify whether unencrypted HTTP is required",
            compliance_references: [],
        },
    ];
}

module.exports = { runMockScan };