"""VEX (Vulnerability Exploitability eXchange) in CycloneDX form. CERT-In v2.0 section 8.4.1.6 asks for exactly
this: per finding, Affected / Not Affected / Fixed / Under Investigation."""
from __future__ import annotations

from ecdat.model import CryptoAsset, ScanResult

SEVERITY = {"EXPOSED": "critical", "ACT_NOW": "high", "MONITOR": "medium", "SAFE": "info"}


def state_for(asset: CryptoAsset) -> tuple[str, str | None, str]:
    """-> (analysis.state, analysis.justification, human text). CycloneDX states:
    resolved | resolved_with_pedigree | exploitable | in_triage | false_positive | not_affected."""
    tier = asset.risk.tier if asset.risk else "MONITOR"
    usage = asset.context.get("usage")
    qclass = asset.risk.quantum_class if asset.risk else asset.context.get("quantum_class")
    if usage == "test":
        return "not_affected", "code_not_reachable", "test-only code path"
    if usage == "comment":
        return "false_positive", "code_not_present", "mentioned in a comment only"
    if usage == "non-security":
        return "not_affected", "requires_configuration", "non-security use of a hash"
    if qclass == "safe":
        return "resolved", None, "quantum-safe"
    if tier in ("EXPOSED", "ACT_NOW"):
        if asset.recommendation and asset.recommendation.hybrid and (asset.props or {}).get("pq_kex"):
            return "not_affected", "protected_by_mitigating_control", "hybrid PQ key exchange in place"
        return "exploitable", None, "quantum-vulnerable and reachable"
    return "in_triage", None, "quantum-vulnerable; low urgency"


def build(result: ScanResult) -> dict:
    vulns = []
    n = 0
    for a in result.assets:
        if not a.risk or a.risk.tier == "SAFE" and a.context.get("usage") not in ("test", "comment", "non-security"):
            continue
        n += 1
        state, just, text = state_for(a)
        a.vex = {"exploitable": "affected", "resolved": "resolved", "not_affected": "not_affected",
                 "false_positive": "not_affected", "in_triage": "in_triage"}[state]
        analysis = {"state": state, "detail": text, "response": ["update"] if state == "exploitable" else []}
        if just:
            analysis["justification"] = just
        vulns.append({
            "bom-ref": f"vuln-{n}",
            "id": f"ECDAT-QV-{n:04d}",
            "source": {"name": "ECDAT quantum risk engine", "url": "https://sih.gov.in/sih2026PS#26164"},
            "ratings": [{"method": "other", "severity": SEVERITY.get(a.risk.tier, "medium"),
                         "justification": "; ".join(a.risk.reasons)[:500]}],
            "cwes": [327] if a.risk.quantum_class in ("broken", "legacy-broken") else [326],
            "description": f"{a.name} ({a.asset_type}) in {a.component}: {a.risk.quantum_class}; tier {a.risk.tier}",
            "detail": a.risk.reason,
            "recommendation": (f"Migrate to {a.recommendation.target}" + (f" (hybrid)" if a.recommendation.hybrid else ""))
            if a.recommendation and a.recommendation.target else "No change required",
            "analysis": analysis,
            "affects": [{"ref": a.bom_ref}],
            "properties": [
                {"name": "ecdat:tier", "value": a.risk.tier},
                {"name": "ecdat:hndl_applicable", "value": str(a.risk.hndl_applicable).lower()},
                {"name": "ecdat:mosca", "value": f"X={a.risk.x:g} Y={a.risk.y:g} Z={a.risk.z:g}"},
            ],
        })
    return {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "vulnerabilities": vulns,
            "metadata": {"timestamp": result.timestamp, "properties": [{"name": "ecdat:z_year", "value": str(result.params.z_year)}]}}
