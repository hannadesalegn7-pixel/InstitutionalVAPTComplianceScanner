const { spawn } = require("child_process");
const path = require("path");

// Sends findings to compliance/map_findings.py and returns them with
// compliance_references filled in. If mapping fails, returns the
// findings unchanged so the scan still works.
function mapCompliance(findings) {
  return new Promise((resolve) => {
    const script = path.join(__dirname, "..", "compliance", "map_findings.py");
    const child = spawn("python3", [script]);

    let out = "";
    const timer = setTimeout(() => child.kill(), 10000);

    child.stdout.on("data", (d) => (out += d));
    child.on("error", () => {
      clearTimeout(timer);
      resolve(findings);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return resolve(findings);
      try {
        resolve(JSON.parse(out));
      } catch {
        resolve(findings);
      }
    });

    child.stdin.on("error", () => {});
    child.stdin.write(JSON.stringify(findings));
    child.stdin.end();
  });
}

module.exports = { mapCompliance };