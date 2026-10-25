"""Rules engine - Member 4 (Compliance and Findings).

Two entry points:

1) evaluate(target, observations)
   Scanner observations -> findings (with compliance_references).

2) map_findings(findings)
   Existing findings in the shared format -> the SAME findings with
   compliance_references filled in. Used by compliance/map_findings.py,
   which the Node backend can call with JSON on stdin.
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
            "rationale": m["mapping_rationale"],
            "verification_status": m["verification_status"],
            "source_verified": ctrl["source_verified"],
        })
    return refs


def evaluate(target, observations):
    """Return a list of findings (shared schema) for scanner observations."""
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


def _to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _merge_references(refs):
    """Merge duplicate controls; the most cautious verification status wins."""
    merged = {}
    order = []
    for r in refs:
        key = (r["framework"], r["reference"])
        if key not in merged:
            merged[key] = dict(r)
            order.append(key)
            continue
        m = merged[key]
        if r["rationale"] not in m["rationale"]:
            m["rationale"] += " | " + r["rationale"]
        if r["verification_status"] != "verified":
            m["verification_status"] = r["verification_status"]
    return [merged[k] for k in order]


def map_findings(findings):
    """Return the same findings with compliance_references filled in.

    Only compliance_references is changed. Every other field (severity,
    evidence, recommendation, ...) is returned exactly as received.
    Findings without a usable port get an empty compliance_references list.
    """
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    result = []
    for f in findings:
        if not isinstance(f, dict):
            result.append(f)
            continue
        out = dict(f)
        port = _to_int(f.get("port"))
        refs = []
        if port is not None:
            obs = {
                "port": port,
                "protocol": str(f.get("protocol") or "tcp").lower(),
                "state": "open",
                "service": f.get("service"),
                "version": f.get("version"),
            }
            for rule in RULES:
                if _matches(rule, obs):
                    refs.extend(_references_for(rule["rule_id"]))
        out["compliance_references"] = _merge_references(refs)
        result.append(out)
    return result
