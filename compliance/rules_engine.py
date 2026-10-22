"""Rules engine - Member 4 (Risk Assessment, Compliance & Reporting).

Usage from the FastAPI backend:
    from compliance.rules_engine import evaluate
    findings = evaluate(target, observations)

observations: list of dicts like
    {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "version": None}
"""
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent


def _load(rel):
    with open(BASE / rel, encoding="utf-8") as f:
        return json.load(f)


RULES = _load("rules/rules.json")
CONTROLS = {c["control_id"]: c for c in _load("controls/controls.json")}
MAPPINGS = _load("mappings/mappings.json")


def _matches(rule, obs):
    c = rule["detection_criteria"]
    if obs.get("state", "open") != "open":
        return False

    match = c.get("match")
    if match == "service_on_unexpected_port":
        expected = c["expected"].get(str(obs.get("service") or "").lower())
        return isinstance(expected, list) and obs["port"] not in expected
    if match == "version_present":
        return bool(obs.get("version"))

    if c.get("protocol") and (obs.get("protocol") or "tcp") != c["protocol"]:
        return False
    ports = c.get("ports") or ([c["port"]] if "port" in c else None)
    if ports and obs["port"] not in ports:
        return False
    return True


def _references_for(rule_id):
    refs = []
    for m in MAPPINGS:
        if m["rule_id"] != rule_id:
            continue
        ctrl = CONTROLS.get(m["control_id"])
        if not ctrl:
            continue
        refs.append({
            "framework": ctrl["framework"],
            "reference": ctrl["reference"],
            "title": ctrl["title"],
            "mapping_rationale": m["mapping_rationale"],
            "verification_status": m["verification_status"],
            "source_verified": ctrl["source_verified"],
        })
    return refs


def evaluate(target, observations):
    """Return a list of findings (shared schema) for the given observations."""
    if not isinstance(observations, list):
        return []
    findings = []
    for obs in observations:
        if not isinstance(obs, dict) or not isinstance(obs.get("port"), int):
            continue
        for rule in RULES:
            if not _matches(rule, obs):
                continue
            svc = obs.get("service") or "unknown service"
            proto = obs.get("protocol") or "tcp"
            evidence = f"{svc} observed on port {obs['port']}/{proto}"
            if obs.get("version"):
                evidence += f" (version: {obs['version']})"
            findings.append({
                "finding_id": f"finding-{len(findings) + 1:03d}",
                "rule_id": rule["rule_id"],
                "title": rule["name"],
                "target": target,
                "port": obs["port"],
                "protocol": proto,
                "service": obs.get("service"),
                "severity": rule["severity"],
                "evidence": evidence,
                "confidence": rule["default_confidence"],
                "recommendation": rule["recommendation"],
                "compliance_references": _references_for(rule["rule_id"]),
            })
    return findings
