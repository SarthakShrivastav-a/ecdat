"""SARIF 2.1.0 export (GitHub code scanning, VS Code SARIF viewer)."""
from __future__ import annotations

from ecdat import __version__
from ecdat.model import ScanResult

LEVEL = {"EXPOSED": "error", "ACT_NOW": "error", "MONITOR": "warning", "SAFE": "note"}


def to_sarif(result: ScanResult) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for a in result.assets:
        tier = a.risk.tier if a.risk else "MONITOR"
        qclass = a.risk.quantum_class if a.risk else "unknown"
        rid = f"ecdat/{a.asset_type}/{a.name}".replace(" ", "_")
        if rid not in rules:
            rules[rid] = {
                "id": rid, "name": f"{a.name} ({a.asset_type})",
                "shortDescription": {"text": f"{a.name}: {qclass}"},
                "fullDescription": {"text": (a.risk.reason if a.risk else "") or f"Cryptographic asset {a.name}"},
                "helpUri": "https://cyclonedx.org/capabilities/cbom/",
                "properties": {"quantum_class": qclass, "primitive": a.primitive},
            }
        loc = a.evidence[0] if a.evidence else None
        msg = f"{a.name} ({a.asset_type}) tier {tier}"
        if a.recommendation and a.recommendation.target:
            msg += f"; recommended: {a.recommendation.target}"
        r = {
            "ruleId": rid, "level": LEVEL.get(tier, "warning"),
            "message": {"text": msg},
            "properties": {"tier": tier, "priority": a.risk.priority if a.risk else 0,
                           "agility": a.agility.total if a.agility else None, "component": a.component,
                           "confidence": a.confidence, "hndl_applicable": a.risk.hndl_applicable if a.risk else False},
        }
        if loc:
            region = {"startLine": max(1, int(loc.line or 1))}
            if loc.snippet:
                region["snippet"] = {"text": loc.snippet[:200]}
            r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": loc.location.replace("\\", "/")}, "region": region}}]
        results.append(r)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ECDAT", "version": __version__, "informationUri": "https://sih.gov.in/sih2026PS",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"z_year": result.params.z_year, "scan": result.name},
        }],
    }
