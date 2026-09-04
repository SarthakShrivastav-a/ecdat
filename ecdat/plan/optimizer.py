"""Budgeted migration plan: greedy knapsack by priority per engineer-week.

Given N engineers for M months, order the non-SAFE assets so the most risk is removed per week of effort,
report the cumulative risk reduction curve, and list what does not fit the budget.
"""
from __future__ import annotations

from ecdat.model import CryptoAsset

WEEKS_PER_MONTH = 4.33
TYPE_TIEBREAK = {"certificate": 0, "protocol": 1, "related-crypto-material": 2, "algorithm": 3, "library": 4}


def _risk_value(a: CryptoAsset) -> float:
    return float(a.risk.priority) if a.risk else 0.0


def _effort(a: CryptoAsset) -> float:
    if a.recommendation and a.recommendation.effort_weeks:
        return max(0.25, float(a.recommendation.effort_weeks))
    return 2.0


def plan(assets: list[CryptoAsset], engineers: int = 4, months: int = 6) -> dict:
    capacity = round(engineers * months * WEEKS_PER_MONTH, 1)
    candidates = [a for a in assets if a.risk and a.risk.tier != "SAFE" and _risk_value(a) > 0]
    total_risk = sum(_risk_value(a) for a in candidates) or 1.0
    ordered = sorted(candidates, key=lambda a: (-(_risk_value(a) / _effort(a)), TYPE_TIEBREAK.get(a.asset_type, 9), -_risk_value(a), a.name))
    items = []
    used = 0.0
    covered = 0.0
    uncovered = []
    for a in ordered:
        eff = _effort(a)
        rv = _risk_value(a)
        if used + eff <= capacity:
            used += eff
            covered += rv
            items.append({
                "bom_ref": a.bom_ref, "name": a.name, "asset_type": a.asset_type, "component": a.component,
                "tier": a.risk.tier, "priority": round(rv, 3), "effort_weeks": eff,
                "risk_per_week": round(rv / eff, 3), "target": a.recommendation.target if a.recommendation else None,
                "cumulative_weeks": round(used, 1), "cumulative_risk_pct": round(100.0 * covered / total_risk, 1),
                "location": a.evidence[0].location if a.evidence else None,
            })
        else:
            uncovered.append({"bom_ref": a.bom_ref, "name": a.name, "asset_type": a.asset_type, "component": a.component,
                              "tier": a.risk.tier, "priority": round(rv, 3), "effort_weeks": eff,
                              "target": a.recommendation.target if a.recommendation else None})
    return {
        "engineers": engineers, "months": months, "capacity_weeks": capacity, "used_weeks": round(used, 1),
        "items": items, "uncovered": uncovered, "covered_pct": round(100.0 * covered / total_risk, 1) if candidates else 100.0,
        "total_risk": round(total_risk, 3), "candidates": len(candidates),
        "exposed_remaining": sum(1 for u in uncovered if u["tier"] == "EXPOSED"),
    }
