# compliance/ (Member 4: Compliance and Findings)

- `rules/rules.json` - security rules (ID, criteria, severity, evidence, what it cannot prove, recommendation)
- `controls/controls.json` - control references with source and verification status
- `mappings/mappings.json` - which rule relates to which control, and why
- `map_findings.py` - reads findings JSON on stdin, prints the same findings with `compliance_references` filled in
- `rules_engine.py` - `evaluate()` (observations -> findings) and `map_findings()` (findings -> findings + references)
- `docs/` - severity criteria, rule catalogue, mapping interface, reference verification log, limitations
- `report.py`, `make_report.py` - optional risk summary and Markdown report (extra, not required by the plan)
- `tests/test_engine.py` - run: `python3 compliance/tests/test_engine.py`

Backend usage: see `docs/mapping-interface.md`.
