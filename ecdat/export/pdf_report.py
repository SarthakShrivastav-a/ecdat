"""PDF report via reportlab: a two-page executive summary plus a technical appendix table."""
from __future__ import annotations

from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ecdat import __version__
from ecdat.model import ScanResult

TIER_LABEL = {"EXPOSED": "ALREADY EXPOSED", "ACT_NOW": "ACT NOW", "MONITOR": "MONITOR", "SAFE": "SAFE"}
TIER_RGB = {"EXPOSED": colors.HexColor("#d7263d"), "ACT_NOW": colors.HexColor("#f46036"),
            "MONITOR": colors.HexColor("#e5b800"), "SAFE": colors.HexColor("#2e9e6a")}


def _p(text: str, style) -> Paragraph:
    return Paragraph(str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"), style)


def write(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    styles = getSampleStyleSheet()
    h1, h2, body = styles["Title"], styles["Heading2"], styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    cell = ParagraphStyle("cell", parent=body, fontSize=7.5, leading=9)
    doc = SimpleDocTemplate(str(p), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"ECDAT report - {result.name}", author=f"ECDAT {__version__}")
    assets = result.assets
    tiers = {t: [a for a in assets if a.risk and a.risk.tier == t] for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE")}
    z = result.params.z_year
    plan = result.plan or {}
    story = [
        _p("ECDAT - Cryptographic Risk Report", h1),
        _p(f"Scan: {result.name} | {result.timestamp[:19]} | ECDAT {__version__} | quantum horizon Z = {z} (user-set) | profile {result.params.profile.upper()}", small),
        Spacer(1, 6 * mm),
        _p("Executive summary", h2),
    ]
    summary = [["Tier", "Assets", "Meaning"],
               ["ALREADY EXPOSED", len(tiers["EXPOSED"]), "Data captured today outlives the migration (Mosca X + Y > Z). Migration alone does not save it."],
               ["ACT NOW", len(tiers["ACT_NOW"]), "Quantum-vulnerable or classically broken; a deadline or the Mosca margin is inside the migration window."],
               ["MONITOR", len(tiers["MONITOR"]), "Vulnerable but short-lived data, signing-only, or ample time."],
               ["SAFE", len(tiers["SAFE"]), "Quantum-safe, or non-security / test-only use."]]
    t = Table([[_p(c, cell) for c in row] for row in summary], colWidths=[34 * mm, 16 * mm, 120 * mm])
    ts = TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe6ee")),
                     ("VALIGN", (0, 0), (-1, -1), "TOP")])
    for i, tier in enumerate(("EXPOSED", "ACT_NOW", "MONITOR", "SAFE"), start=1):
        ts.add("TEXTCOLOR", (0, i), (0, i), TIER_RGB[tier])
    t.setStyle(ts)
    story += [t, Spacer(1, 4 * mm)]
    hndl = sum(1 for a in assets if a.risk and a.risk.hndl_applicable)
    story.append(_p(f"{len(assets)} cryptographic assets were inventoried in CycloneDX 1.7; {hndl} protect data that an adversary can record today "
                    f"(harvest-now-decrypt-later). {len(tiers['EXPOSED']) + len(tiers['ACT_NOW'])} assets must migrate first.", body))
    dst = {"cii": (2027, 2028, 2029), "enterprise": (2028, 2030, 2033)}.get(result.params.profile, (2028, 2030, 2033))
    story.append(_p(f"India (DST / National Quantum Mission, {result.params.profile.upper()} profile): inventory and CBOM by {dst[0]}, "
                    f"no new classical-only deployments after {dst[1]}, quantum-safe-only trust chains by {dst[2]}.", body))
    if plan:
        story += [Spacer(1, 3 * mm), _p("Migration plan", h2),
                  _p(f"{plan.get('engineers')} engineers x {plan.get('months')} months = {plan.get('capacity_weeks')} engineer-weeks; "
                     f"{plan.get('used_weeks')} weeks used remove {plan.get('covered_pct')}% of quantum risk; "
                     f"{len(plan.get('uncovered', []))} item(s) do not fit ({plan.get('exposed_remaining', 0)} still EXPOSED).", body)]
        rows = [["#", "Asset", "Component", "Tier", "Target", "Effort wk", "Cum. wk", "Cum. risk %"]]
        for i, it in enumerate(plan.get("items", [])[:25], start=1):
            rows.append([i, it["name"], it["component"], TIER_LABEL.get(it["tier"], it["tier"]), it.get("target") or "-", it["effort_weeks"], it["cumulative_weeks"], it["cumulative_risk_pct"]])
        pt = Table([[_p(c, cell) for c in r] for r in rows], colWidths=[8 * mm, 30 * mm, 30 * mm, 24 * mm, 30 * mm, 16 * mm, 16 * mm, 18 * mm], repeatRows=1)
        pt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe6ee"))]))
        story.append(pt)
    story += [Spacer(1, 3 * mm), _p("Honesty notes", h2),
              _p(f"Z ({z}) is a user-set assumption anchored to the Global Risk Institute 2025 survey (CRQC 28-49% within 10 years, 51-70% within 15). "
                 "Mosca's inequality is applied only to confidentiality primitives; signatures and hashes are deadline-driven. Binary findings are best-effort. "
                 "Every finding carries confidence and file:line evidence. Patches are suggestions and are never applied automatically.", small),
              PageBreak(), _p("Technical appendix: all assets", h2)]
    rows = [["Tier", "Asset", "Type", "Component", "Where", "Class", "X/Y/Z", "Agility", "Recommendation", "Conf."]]
    for a in sorted(assets, key=lambda a: -(a.risk.priority if a.risk else 0)):
        r, rec, e = a.risk, a.recommendation, (a.evidence[0] if a.evidence else None)
        rows.append([TIER_LABEL.get(r.tier, "") if r else "", a.name, a.asset_type, a.component,
                     f"{e.location}:{e.line}" if e and e.line else (e.location if e else ""),
                     (r.quantum_class + (" HNDL" if r.hndl_applicable else "")) if r else "",
                     f"{a.lifetime_years:g}/{r.y:g}/{r.z:g}" if r and a.lifetime_years is not None else "",
                     a.agility.total if a.agility else "", (rec.target or "-") if rec else "-", a.confidence])
    at = Table([[_p(c, cell) for c in row] for row in rows], colWidths=[18 * mm, 20 * mm, 16 * mm, 22 * mm, 34 * mm, 18 * mm, 14 * mm, 12 * mm, 20 * mm, 10 * mm], repeatRows=1)
    at.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe6ee")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(at)
    doc.build(story)
    return p
