"""Evaluation against ground truth (tests/fixtures/zoo/truth.yaml): precision / recall / F1 per collector + overall.
Truth items: {component, name, asset_type=algorithm, key_size?, usage?}. Negatives: things that must NOT match."""
from __future__ import annotations

from pathlib import Path

import yaml

from ecdat.model import ScanResult

DEFAULT_TRUTH = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "zoo" / "truth.yaml"
GATES = {"precision": 0.85, "recall": 0.95}


def _key(comp: str, name: str, asset_type: str) -> tuple:
    return (comp, name, asset_type)


def _matches(item: dict, asset) -> bool:
    if item["component"] != asset.component or item["name"] != asset.name:
        return False
    if item.get("asset_type", "algorithm") != asset.asset_type:
        return False
    if item.get("key_size") is not None and asset.key_size != item["key_size"]:
        return False
    if item.get("usage") is not None and asset.context.get("usage") != item["usage"]:
        return False
    return True


def evaluate(result: ScanResult, truth_path: str | Path | None = None) -> dict:
    truth = yaml.safe_load(Path(truth_path or DEFAULT_TRUTH).read_text(encoding="utf-8")) or {}
    expected = truth.get("expected") or []
    negatives = truth.get("negatives") or []
    allowed = truth.get("allowed_extras") or []
    scored = [a for a in result.assets if a.asset_type in ("algorithm", "certificate", "protocol")
              and not a.context.get("from_library_only") and a.context.get("usage") not in ("comment",)]
    tp, fn, matched_assets = [], [], set()
    for item in expected:
        hits = [a for a in scored if _matches(item, a)]
        if hits:
            tp.append(item)
            matched_assets.update(id(a) for a in hits)
        else:
            fn.append(item)
    extras = [a for a in scored if id(a) not in matched_assets]
    allowed_hits = [a for a in extras if any(_matches(x, a) for x in allowed)]
    fp = [a for a in extras if a not in allowed_hits]
    neg_hits = [(n, a) for n in negatives for a in scored if _matches(n, a)]
    fp_total = len(fp) + len(neg_hits)
    precision = len(tp) / (len(tp) + fp_total) if (tp or fp_total) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    per_collector: dict[str, dict] = {}
    for a in scored:
        for c in a.context.get("collectors", []) or [e.collector for e in a.evidence]:
            d = per_collector.setdefault(c, {"assets": 0, "matched": 0})
            d["assets"] += 1
            d["matched"] += 1 if id(a) in matched_assets or a in allowed_hits else 0
    for c, d in per_collector.items():
        d["precision"] = round(d["matched"] / d["assets"], 3) if d["assets"] else None
    rep = {"tp": len(tp), "fp": fp_total, "fn": len(fn), "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
           "expected": len(expected), "scored_assets": len(scored), "allowed_extras_hit": len(allowed_hits),
           "missed": [f"{i['component']}:{i['name']}{'-' + str(i['key_size']) if i.get('key_size') else ''}" for i in fn],
           "extra": [f"{a.component}:{a.name}{'-' + str(a.key_size) if a.key_size else ''} ({a.asset_type}, {','.join(a.context.get('collectors', []))}, {a.confidence})" for a in fp],
           "negative_hits": [f"{n['component']}:{n['name']} matched {a.bom_ref}" for n, a in neg_hits],
           "per_collector": per_collector,
           "gates": {"precision_min": GATES["precision"], "recall_min": GATES["recall"],
                     "passed": precision >= GATES["precision"] and recall >= GATES["recall"]}}
    return rep


def print_report(rep: dict, console=None) -> None:
    from rich.console import Console
    from rich.table import Table
    console = console or Console()
    t = Table(title=f"evaluation: precision {rep['precision']}  recall {rep['recall']}  F1 {rep['f1']}  ({'PASS' if rep['gates']['passed'] else 'FAIL'} vs gates {rep['gates']['precision_min']}/{rep['gates']['recall_min']})")
    t.add_column("metric"); t.add_column("value", justify="right")
    for k in ("tp", "fp", "fn", "expected", "scored_assets", "allowed_extras_hit"):
        t.add_row(k, str(rep[k]))
    console.print(t)
    t2 = Table(title="per collector (assets it contributed to that are in the truth set)")
    t2.add_column("collector"); t2.add_column("assets", justify="right"); t2.add_column("matched", justify="right"); t2.add_column("precision", justify="right")
    for c, d in sorted(rep["per_collector"].items()):
        t2.add_row(c, str(d["assets"]), str(d["matched"]), str(d["precision"]))
    console.print(t2)
    if rep["missed"]:
        console.print("[red]missed:[/] " + ", ".join(rep["missed"]))
    if rep["extra"]:
        console.print("[yellow]extra (counted as FP):[/] " + "; ".join(rep["extra"]))
    if rep["negative_hits"]:
        console.print("[red]negatives hit:[/] " + "; ".join(rep["negative_hits"]))
