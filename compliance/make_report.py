"""Create a sample report: python3 compliance/make_report.py"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from compliance.rules_engine import evaluate
from compliance.report import generate_markdown

obs_file = ROOT / "compliance" / "samples" / "sample-observations.json"
observations = json.loads(obs_file.read_text(encoding="utf-8"))
findings = evaluate("192.168.1.10", observations)
out = ROOT / "compliance" / "docs" / "sample-report.md"
out.write_text(generate_markdown("192.168.1.10", findings), encoding="utf-8")
print("Report created:", out)
