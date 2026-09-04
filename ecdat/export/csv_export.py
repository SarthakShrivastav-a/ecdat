"""CSV export (RFC 4180), hardened against spreadsheet formula injection."""
from __future__ import annotations

import csv
import io
from pathlib import Path

from ecdat.model import ScanResult

COLUMNS = ["bom_ref", "component", "asset_type", "name", "family", "primitive", "key_size", "mode", "curve", "oid",
           "confidence", "usage", "zone", "transit", "at_rest", "signing_only", "quantum_class", "hndl_applicable",
           "lifetime_years", "migration_years", "z_years", "mosca_gap", "tier", "priority", "agility", "deadline_year",
           "recommended", "alternative", "hybrid", "effort_weeks", "vex", "location", "line", "collectors"]


def harden(value) -> str:
    s = "" if value is None else str(value)
    if s and s[0] in "=+-@\t\r":
        return "'" + s
    return s


def rows(result: ScanResult) -> list[dict]:
    out = []
    for a in result.assets:
        r = a.risk
        rec = a.recommendation
        e = a.evidence[0] if a.evidence else None
        out.append({
            "bom_ref": a.bom_ref, "component": a.component, "asset_type": a.asset_type, "name": a.name, "family": a.family,
            "primitive": a.primitive, "key_size": a.key_size or (a.props or {}).get("key_size"), "mode": a.mode, "curve": a.curve, "oid": a.oid,
            "confidence": a.confidence, "usage": a.context.get("usage"), "zone": (a.exposure or {}).get("zone"),
            "transit": (a.exposure or {}).get("transit"), "at_rest": (a.exposure or {}).get("at_rest"),
            "signing_only": (a.exposure or {}).get("signing_only"),
            "quantum_class": r.quantum_class if r else None, "hndl_applicable": r.hndl_applicable if r else None,
            "lifetime_years": a.lifetime_years, "migration_years": r.y if r else None, "z_years": r.z if r else None,
            "mosca_gap": r.mosca_gap if r else None, "tier": r.tier if r else None, "priority": r.priority if r else None,
            "agility": a.agility.total if a.agility else None, "deadline_year": r.deadline_year if r else None,
            "recommended": rec.target if rec else None, "alternative": rec.alternative if rec else None,
            "hybrid": rec.hybrid if rec else None, "effort_weeks": rec.effort_weeks if rec else None, "vex": a.vex,
            "location": e.location if e else None, "line": e.line if e else None,
            "collectors": "|".join(sorted({x.collector for x in a.evidence})),
        })
    return out


def render(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=COLUMNS, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    w.writeheader()
    for r in rows(result):
        w.writerow({k: harden(r.get(k)) for k in COLUMNS})
    return buf.getvalue()


def write(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(render(result), encoding="utf-8", newline="")
    return p
