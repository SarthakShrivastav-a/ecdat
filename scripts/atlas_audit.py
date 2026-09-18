"""Hand-audit a random sample of flagged atlas findings to measure real-world precision.

    python scripts/atlas_audit.py sample [-n 60]   # -> out/atlas/audit_sample.md (evidence to read) + audit_labels.json (to fill)
    python scripts/atlas_audit.py score            # -> out/atlas/audit.json {n, correct, precision, wilson_95}

Population: every asset tiered EXPOSED / ACT_NOW / MONITOR that was observed in the project's own code, config,
certificates or binaries (library-capability-only entries excluded) and classified as production use. The seed is
fixed (26164) so the sample is reproducible. A finding is "correct" when the named algorithm really is used at that
location as a security control, and its quantum class is right. Everything else is a false positive.
"""
from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "out" / "atlas"
SEED = 26164


def population() -> list[dict]:
    rows = []
    for d in sorted((OUT / "scans").iterdir()):
        res = d / "result.json"
        if not d.is_dir() or not res.exists():
            continue
        r = json.loads(res.read_text(encoding="utf-8"))
        for a in r["assets"]:
            ctx = a.get("context") or {}
            tier = (a.get("risk") or {}).get("tier")
            if tier not in ("EXPOSED", "ACT_NOW", "MONITOR"):
                continue
            if ctx.get("from_library_only") and not ctx.get("corroborated"):
                continue
            if ctx.get("usage") in ("test", "comment", "non-security"):
                continue
            rows.append({"repo": d.name.replace("__", "/"), "bom_ref": a["bom_ref"], "type": a["asset_type"], "name": a["name"],
                         "tier": tier, "class": (a.get("risk") or {}).get("quantum_class"),
                         "evidence": [{"collector": e.get("collector"), "at": f"{e.get('location')}:{e.get('line')}",
                                       "snippet": str(e.get("snippet") or "")[:200]} for e in (a.get("evidence") or [])[:3]]})
    return rows


def sample(n: int) -> None:
    pop = population()
    pick = random.Random(SEED).sample(pop, min(n, len(pop)))
    lines = [f"# Audit sample: {len(pick)} of {len(pop)} flagged findings (seed {SEED})", ""]
    for i, p in enumerate(pick, 1):
        lines.append(f"## {i}. {p['repo']} · {p['type']} **{p['name']}** · {p['tier']} · {p['class']}")
        lines += [f"- {e['collector']} `{e['at']}` — `{e['snippet']}`" for e in p["evidence"]] + [""]
    (OUT / "audit_sample.md").write_text("\n".join(lines), encoding="utf-8")
    labels_path = OUT / "audit_labels.json"
    old = json.loads(labels_path.read_text(encoding="utf-8")) if labels_path.exists() else {}
    labels = {f"{p['repo']}|{p['bom_ref']}": old.get(f"{p['repo']}|{p['bom_ref']}", {"correct": None, "note": ""}) for p in pick}
    labels_path.write_text(json.dumps(labels, indent=1), encoding="utf-8")
    print(f"sampled {len(pick)} of {len(pop)} -> {OUT / 'audit_sample.md'}")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if not n:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(100 * (c - h), 1), round(100 * (c + h), 1)


def score() -> None:
    labels = json.loads((OUT / "audit_labels.json").read_text(encoding="utf-8"))
    done = [v for v in labels.values() if v["correct"] is not None]
    if len(done) != len(labels):
        raise SystemExit(f"{len(labels) - len(done)} findings still unlabelled")
    k = sum(1 for v in done if v["correct"])
    lo, hi = wilson(k, len(done))
    out = {"n": len(done), "correct": k, "precision": round(100 * k / len(done), 1), "wilson_95": [lo, hi], "seed": SEED,
           "population": len(population()), "false_positives": [{"id": key, "note": v["note"]} for key, v in labels.items() if not v["correct"]]}
    (OUT / "audit.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({k2: out[k2] for k2 in ("n", "correct", "precision", "wilson_95", "population")}))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["sample", "score"])
    ap.add_argument("-n", type=int, default=60)
    a = ap.parse_args()
    sample(a.n) if a.step == "sample" else score()
