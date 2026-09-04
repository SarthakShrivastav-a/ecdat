"""Data lifetime (Mosca's X) and business criticality.

infer():  explicit component override -> hints in component name / path / evidence locations / snippets ->
          generic default. The most conservative (longest-lived) matching class wins.
criticality_multiplier(): QRAMM-style profile multiplier 0.8 - 1.5x from data_classes.yaml.
"""
from __future__ import annotations

import re

from ecdat.knowledge import KnowledgeBase
from ecdat.model import Component, CryptoAsset

_DEFAULT_CLASSES = {
    "defence": {"years": 30, "hints": ["classified", "defence", "defense", "military"]},
    "health": {"years": 25, "hints": ["patient", "medical", "health"]},
    "identity": {"years": 20, "hints": ["identity", "kyc", "passport", "aadhaar"]},
    "financial": {"years": 10, "hints": ["payment", "bank", "card", "ledger"]},
    "pii": {"years": 7, "hints": ["user", "customer", "email"]},
    "logs": {"years": 1, "hints": ["log", "audit"]},
    "session": {"years": 0.1, "hints": ["session", "token", "cache"]},
    "generic": {"years": 5, "hints": []},
}
_DEFAULT_CRIT = {"low": 0.8, "medium": 1.0, "high": 1.25, "critical": 1.5}


def _classes(kb: KnowledgeBase | None) -> dict:
    if kb and kb.data_classes.get("classes"):
        return kb.data_classes["classes"]
    return _DEFAULT_CLASSES


def _tokens(*texts: str) -> set[str]:
    toks: set[str] = set()
    for t in texts:
        if not t:
            continue
        for w in re.split(r"[^A-Za-z0-9]+", t):
            if w:
                toks.add(w.lower())
        # camelCase splits
        for w in re.findall(r"[A-Z][a-z]+", t):
            toks.add(w.lower())
    return toks


def infer(component: Component | None, asset: CryptoAsset, kb: KnowledgeBase | None = None) -> tuple[float, str, str]:
    classes = _classes(kb)
    explicit = (component.data_class if component else None) or asset.context.get("data_class")
    if explicit and explicit in classes:
        years = float(classes[explicit]["years"])
        asset.lifetime_years, asset.data_class = years, explicit
        return years, explicit, f"explicit data class '{explicit}' on component"

    texts = [component.name if component else "", component.path if component and component.path else ""]
    for e in asset.evidence:
        texts.append(e.location or "")
        texts.append(e.snippet or "")
    toks = _tokens(*texts)
    best: tuple[float, str, str] | None = None
    for cls, spec in classes.items():
        hits = [h for h in spec.get("hints", []) if h.lower() in toks]
        if hits:
            cand = (float(spec["years"]), cls, f"matched hint '{hits[0]}' -> {cls}")
            if best is None or cand[0] > best[0]:
                best = cand
    if best is None:
        years = float(classes.get("generic", {"years": 5})["years"])
        best = (years, "generic", "no data-class signal; generic default")
    asset.lifetime_years, asset.data_class = best[0], best[1]
    return best


def criticality_multiplier(level: str | None, kb: KnowledgeBase | None = None) -> float:
    table = (kb.data_classes.get("criticality") if kb and kb.data_classes else None) or _DEFAULT_CRIT
    if not level:
        return float(table.get("medium", 1.0))
    return float(table.get(str(level).lower(), table.get("medium", 1.0)))


def apply(assets: list[CryptoAsset], components: list[Component], kb: KnowledgeBase | None = None) -> None:
    by_ref = {c.bom_ref: c for c in components}
    by_name = {c.name: c for c in components}
    for a in assets:
        comp = by_ref.get(a.component) or by_name.get(a.component)
        years, cls, reason = infer(comp, a, kb)
        a.context["lifetime_reason"] = reason
        crit = (comp.criticality if comp else None) or a.criticality or "medium"
        a.criticality = crit
        a.criticality_multiplier = criticality_multiplier(crit, kb)
