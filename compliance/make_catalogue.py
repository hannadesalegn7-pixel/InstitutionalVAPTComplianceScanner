"""Create the rule catalogue document: python3 compliance/make_catalogue.py"""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
rules = json.loads((BASE / "rules" / "rules.json").read_text(encoding="utf-8"))
md = [
    "# Rule Catalogue",
    "",
    "| ID | Name | Severity | Evidence required | Cannot prove |",
    "|---|---|---|---|---|",
]
for r in rules:
    md.append(
        f"| {r['rule_id']} | {r['name']} | {r['severity']} | "
        f"{r['evidence_required']} | {r['cannot_prove']} |"
    )
(BASE / "docs" / "rule-catalogue.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("Created compliance/docs/rule-catalogue.md")
