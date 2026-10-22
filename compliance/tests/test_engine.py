import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from compliance.rules_engine import evaluate
from compliance.report import summarize, generate_markdown

T = "192.168.1.10"
sample = json.loads(
    (ROOT / "compliance/samples/sample-observations.json").read_text(encoding="utf-8")
)


def ids(findings):
    return [f["rule_id"] for f in findings]


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
        assert ref["mapping_rationale"] and ref["verification_status"]
print("8 OK: sample works, every mapping has a rationale")

s = summarize(r)
assert s["overall_risk"] == "high" and s["total_findings"] == len(r)
assert summarize([])["overall_risk"] == "none"
print("9 OK: risk summary works")

md = generate_markdown(T, r)
assert "Security Assessment Report" in md and "Limitations" in md
assert "No findings" in generate_markdown(T, [])
print("10 OK: report generation works")

print("ALL TESTS PASSED")
