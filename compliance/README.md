# compliance/ (Member 4)

Risk assessment, compliance mapping and reporting.

- `rules/rules.json` - security rules (severity, evidence, recommendation)
- `controls/controls.json` - control references (NIST, CIS, Ethiopian law)
- `mappings/mappings.json` - which rule relates to which control, and why
- `rules_engine.py` - `evaluate(target, observations)` returns findings
- `report.py` - `summarize(findings)` and `generate_markdown(target, findings)`
- `tests/test_engine.py` - run: `python3 compliance/tests/test_engine.py`

FastAPI usage:

    from compliance.rules_engine import evaluate
    from compliance.report import summarize, generate_markdown

Observations format: list of dicts with keys port, protocol, state, service, version.
