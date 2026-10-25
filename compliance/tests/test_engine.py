import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from compliance.rules_engine import evaluate, map_findings
from compliance.report import summarize, generate_markdown

T = "192.168.1.10"
sample = json.loads(
    (ROOT / "compliance/samples/sample-observations.json").read_text(encoding="utf-8")
)
sample_findings = json.loads(
    (ROOT / "compliance/samples/sample-findings.json").read_text(encoding="utf-8")
)


def ids(findings):
    return [f["rule_id"] for f in findings]


# ---------- evaluate(): observations -> findings ----------
r = evaluate(T, [{"port": 23, "protocol": "tcp", "state": "open", "service": "telnet"}])
assert ids(r) == ["R-001"], ids(r)
assert r[0]["severity"] == "high"
assert any("Ethiopia" in ref["framework"] for ref in r[0]["compliance_references"])
print("1 OK: Telnet -> R-001 high, with controls incl. Ethiopian one")

r = evaluate(T, [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}])
assert ids(r) == ["R-003"] and r[0]["severity"] == "low"
print("2 OK: HTTP -> R-003 low")

r = evaluate(T, [{"port": 8888, "protocol": "tcp", "state": "open", "service": "http"}])
assert ids(r) == ["R-009"] and r[0]["confidence"] == "needs_manual_review"
print("3 OK: http on 8888 -> R-009 manual review")

assert evaluate(T, []) == []
print("4 OK: no ports -> no findings")

r = evaluate(T, [{"port": 445, "protocol": "tcp", "state": "open"}])
assert ids(r) == ["R-004"]
print("5 OK: missing service field handled")

assert evaluate(T, [{"port": 23, "protocol": "tcp", "state": "closed", "service": "telnet"}]) == []
print("6 OK: closed port ignored")

assert evaluate(T, None) == []
assert evaluate(T, [{"service": "x"}, "bad", 5]) == []
print("7 OK: bad input does not crash")

r = evaluate(T, sample)
assert len(r) >= 4
for f in r:
    for ref in f["compliance_references"]:
        assert ref["rationale"] and ref["verification_status"]
print("8 OK: sample works, every mapping has a rationale")

s = summarize(r)
assert s["overall_risk"] == "high" and s["total_findings"] == len(r)
assert summarize([])["overall_risk"] == "none"
print("9 OK: risk summary works")

md = generate_markdown(T, r)
assert "Security Assessment Report" in md and "Limitations" in md
assert "No findings" in generate_markdown(T, [])
print("10 OK: report generation works")

# ---------- map_findings(): findings -> same findings + references ----------
out = map_findings(sample_findings)
assert len(out) == len(sample_findings)
telnet = out[0]
assert telnet["severity"] == "high" and telnet["recommendation"] == "Disable Telnet and use SSH."
refs = {(x["framework"], x["reference"]) for x in telnet["compliance_references"]}
assert ("NIST SP 800-53 Rev 5", "AC-17") in refs and ("NIST SP 800-53 Rev 5", "SC-8") in refs
for x in telnet["compliance_references"]:
    assert x["rationale"] and x["verification_status"] in ("verified", "needs_manual_review")
print("11 OK: map_findings fills references for Telnet")

for before, after in zip(sample_findings, out):
    for key in before:
        if key != "compliance_references":
            assert before[key] == after[key], key
assert sample_findings[0]["compliance_references"] == []
print("12 OK: only compliance_references changes; input not modified")

assert out[3]["compliance_references"] == []
print("13 OK: finding without port -> empty references, no crash")

r = map_findings([{"finding_id": "x", "port": "23", "protocol": "TCP", "service": "Telnet"}])
assert len(r[0]["compliance_references"]) > 0
assert map_findings([]) == []
assert map_findings([5, "bad"]) == [5, "bad"]
try:
    map_findings("not a list")
    raise AssertionError("should raise")
except ValueError:
    pass
print("14 OK: string port, upper case, odd items handled")

# ---------- command line script, as the backend will call it ----------
script = str(ROOT / "compliance" / "map_findings.py")
good = subprocess.run(
    [sys.executable, script], input=json.dumps(sample_findings),
    capture_output=True, text=True, timeout=30,
)
assert good.returncode == 0, good.stderr
parsed = json.loads(good.stdout)
assert len(parsed) == len(sample_findings)
assert len(parsed[0]["compliance_references"]) > 0
print("15 OK: map_findings.py works with stdin/stdout")

bad = subprocess.run(
    [sys.executable, script], input="this is not json",
    capture_output=True, text=True, timeout=30,
)
assert bad.returncode == 1
assert json.loads(bad.stdout)["error"]["code"] == "INVALID_JSON"
bad2 = subprocess.run(
    [sys.executable, script], input='{"a": 1}',
    capture_output=True, text=True, timeout=30,
)
assert bad2.returncode == 1
assert json.loads(bad2.stdout)["error"]["code"] == "INVALID_INPUT"
print("16 OK: bad input gives structured error and exit code 1")

print("ALL TESTS PASSED")
