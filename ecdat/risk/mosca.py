"""Mosca's inequality, tiers and priority.

  X + Y > Z  ->  already exposed        (only for confidentiality primitives that are capturable: HNDL)
  X  = data lifetime in years           (enrich.lifetime)
  Y  = migration time in years          (enrich.agility.y_years)
  Z  = years until a CRQC               (params.z_year - params.now_year; a slider, never a constant)

Tiers: EXPOSED / ACT_NOW / MONITOR / SAFE. Signatures, hashes and MACs are never EXPOSED: they get
deadline-driven ACT_NOW / MONITOR.
"""
from __future__ import annotations

from ecdat.knowledge import KnowledgeBase
from ecdat.model import CryptoAsset, RiskAssessment, ScanParams, ScanResult
from ecdat.risk import frameworks, quantum

Z_PRESETS = {"aggressive": 2032, "nist": 2035, "gri": 2041}
TIER_WEIGHT = {"EXPOSED": 3.0, "ACT_NOW": 2.0, "MONITOR": 1.0, "SAFE": 0.0}
SLACK_YEARS = 2.0


def assess(asset: CryptoAsset, params: ScanParams, kb: KnowledgeBase | None = None) -> RiskAssessment:
    q = {"quantum_class": asset.context.get("quantum_class"), "reason": "", "hndl_applicable": asset.context.get("hndl_applicable", False)}
    if kb is not None:
        q = quantum.classify(asset, kb)
    qclass = q.get("quantum_class") or "unknown"
    hndl = bool(q.get("hndl_applicable"))
    usage = asset.context.get("usage")
    x = float(asset.lifetime_years if asset.lifetime_years is not None else 5.0)
    y = float(asset.agility.y_years if asset.agility else params.y_default)
    z = float(params.z_years)
    gap = x + y - z
    reasons: list[str] = []
    exposure = asset.exposure or {}
    over = frameworks.overlays(asset, params, kb) if kb is not None else (asset.risk.overlays if asset.risk else [])
    deadline = frameworks.earliest_deadline(over)

    if usage in ("non-security", "test", "comment"):
        tier = "SAFE"
        reasons.append(f"usage is {usage}: not a production security control")
    elif qclass == "safe":
        tier = "SAFE"
        reasons.append("quantum-safe algorithm or parameter set")
    elif qclass == "unknown":
        tier = "MONITOR"
        reasons.append("could not classify; review manually")
    elif hndl and gap > 0 and qclass == "broken":
        tier = "EXPOSED"
        reasons.append(f"Mosca: X {x:g} + Y {y:g} = {x + y:g} > Z {z:g}: data captured today outlives the migration")
    elif qclass == "legacy-broken":
        tier = "ACT_NOW"
        reasons.append("classically broken or below minimum strength today, independent of quantum")
    elif qclass == "weakened" and hndl and gap > 0:
        tier = "ACT_NOW"
        reasons.append(f"Grover-weakened and Mosca gap {gap:g} y: move to a 256-bit parameter set (AES-256 / SHA-384)")
    elif qclass == "broken" and (gap > -SLACK_YEARS or (deadline is not None and deadline - params.now_year <= y + 1)):
        tier = "ACT_NOW"
        if gap > -SLACK_YEARS:
            reasons.append(f"Mosca margin only {-gap:g} year(s) (X {x:g} + Y {y:g} vs Z {z:g})")
        if deadline is not None and deadline - params.now_year <= y + 1:
            reasons.append(f"framework deadline {deadline} is within the {y:g}-year migration window")
    elif qclass in ("broken", "weakened"):
        tier = "MONITOR"
        reasons.append("quantum-vulnerable but short-lived data, signing-only, or ample migration time")
    else:
        tier = "MONITOR"

    # A dependency that *can* provide an algorithm is inventory, not evidence of use. Keep it in the CBOM
    # (CERT-In 8.4.2.4 dependency mapping) but never let it drive ACT_NOW/EXPOSED or the migration plan.
    capability_only = bool(asset.context.get("from_library_only")) and not asset.context.get("corroborated")
    if capability_only and tier in ("EXPOSED", "ACT_NOW"):
        tier = "MONITOR"
        reasons.append("library capability only: the dependency provides this algorithm but no use was observed in this codebase")

    if not hndl and qclass in ("broken", "weakened") and exposure.get("signing_only"):
        reasons.append("signature/authentication use: harvest-now-decrypt-later does not apply; deadline-driven")

    zone_mult = 1.5 if exposure.get("zone") == "external" else 1.0
    legacy_bonus = 0.5 if qclass == "legacy-broken" and tier != "SAFE" else 0.0
    priority = (asset.criticality_multiplier or 1.0) * (TIER_WEIGHT[tier] + legacy_bonus) * zone_mult * (1 + min(x, 30.0) / 30.0)
    if capability_only:
        priority = 0.0
    ra = RiskAssessment(quantum_class=qclass, reason=q.get("reason", ""), hndl_applicable=hndl, x=x, y=y, z=z,
                        mosca_gap=round(gap, 2), tier=tier, priority=round(priority, 3), deadline_year=deadline,
                        overlays=over, reasons=reasons)
    asset.risk = ra
    asset.context["tier"] = tier
    return ra


def apply(assets: list[CryptoAsset], params: ScanParams, kb: KnowledgeBase) -> None:
    for a in assets:
        assess(a, params, kb)


def recompute(result: ScanResult, params: ScanParams, kb: KnowledgeBase | None = None) -> ScanResult:
    """Re-assess every asset in place (the Z slider / budget change path). Returns the same result object."""
    kb = kb or KnowledgeBase()
    result.params = params
    for a in result.assets:
        assess(a, params, kb)
    # update the risk counts, keep everything the scan measured (collectors, CERT-In, runtimes, timings)
    result.stats = {**(result.stats or {}), **summarize(result.assets)}
    result.stats["z_year"] = params.z_year
    return result


def summarize(assets: list[CryptoAsset]) -> dict:
    tiers = {"EXPOSED": 0, "ACT_NOW": 0, "MONITOR": 0, "SAFE": 0}
    classes: dict[str, int] = {}
    hndl = 0
    capability_only = 0
    for a in assets:
        if a.risk:
            tiers[a.risk.tier] = tiers.get(a.risk.tier, 0) + 1
            classes[a.risk.quantum_class] = classes.get(a.risk.quantum_class, 0) + 1
            hndl += int(a.risk.hndl_applicable)
        capability_only += int(bool(a.context.get("from_library_only")) and not a.context.get("corroborated"))
    return {"assets": len(assets), "tiers": tiers, "quantum_classes": classes, "hndl_applicable": hndl,
            "library_capability_only": capability_only}
