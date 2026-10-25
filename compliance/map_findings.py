#!/usr/bin/env python3
"""Fill compliance_references on findings.

Reads a JSON list of findings from stdin and prints the same findings, with
compliance_references filled in, as JSON on stdout.

    python3 compliance/map_findings.py < findings.json

Exit code 0 = success. Exit code 1 = bad input; stdout then holds
{"error": {"code": "...", "message": "..."}}.
Standard library only, no extra packages needed.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from compliance.rules_engine import map_findings  # noqa: E402


def fail(code, message):
    print(json.dumps({"error": {"code": code, "message": message}}))
    sys.exit(1)


def main():
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        fail("INVALID_JSON", f"Input is not valid JSON: {exc.msg}")

    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        data["findings"] = map_findings(data["findings"])
        print(json.dumps(data, ensure_ascii=False))
        return
    if not isinstance(data, list):
        fail("INVALID_INPUT", "Expected a JSON list of findings.")
    print(json.dumps(map_findings(data), ensure_ascii=False))


if __name__ == "__main__":
    main()
