const { execFile } = require("child_process");
const path = require("path");

function runScan(target) {
  return new Promise((resolve, reject) => {
    execFile(
      "python3",
      [path.join(__dirname, "run_scan.py"), target],
      { timeout: 75000 },
      (error, stdout) => {
        if (error) return reject(new Error("Scanner failed to run."));

        let result;
        try {
          result = JSON.parse(stdout);
        } catch {
          return reject(new Error("Scanner returned invalid output."));
        }

        if (result.status !== "completed") {
          return reject(new Error(result.error || "Scan failed."));
        }

        resolve(
          result.findings.map((f) => ({
            finding_id: f.id,
            title: f.title,
            target: result.target,
            port: f.port,
            protocol: f.protocol,
            service: f.service,
            version: f.version,
            severity: f.severity,
            evidence: f.evidence,
            confidence: "observed",
            recommendation: f.recommendation,
            compliance_references: [],
          }))
        );
      }
    );
  });
}

module.exports = { runScan };