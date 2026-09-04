"""Self-contained HTML report: executive summary, tier sections, risk x agility 2x2 (inline SVG), migration plan,
CERT-In completeness, framework overlays, and a methodology / honesty section."""
from __future__ import annotations

import html
from pathlib import Path

from ecdat import __version__
from ecdat.model import CryptoAsset, ScanResult

TIER_LABEL = {"EXPOSED": "ALREADY EXPOSED", "ACT_NOW": "ACT NOW", "MONITOR": "MONITOR", "SAFE": "SAFE"}
TIER_COLOR = {"EXPOSED": "#d7263d", "ACT_NOW": "#f46036", "MONITOR": "#e5b800", "SAFE": "#2e9e6a"}
CSS = """
body{font-family:'IBM Plex Sans',Segoe UI,Arial,sans-serif;background:#0b1220;color:#e6edf3;margin:0;padding:32px;max-width:1200px}
h1,h2,h3{font-weight:600;letter-spacing:.2px}h1{font-size:28px;margin:0 0 4px}h2{margin-top:36px;border-bottom:1px solid #22304a;padding-bottom:6px}
.sub{color:#8ea0b8;margin-bottom:24px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.tile{background:#121c30;border:1px solid #22304a;border-radius:10px;padding:14px}.tile .n{font-size:30px;font-weight:700}
.tile .l{color:#8ea0b8;font-size:12px;text-transform:uppercase;letter-spacing:1px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid #22304a;padding:6px 8px;text-align:left;vertical-align:top}
th{color:#8ea0b8;font-weight:600}code{font-family:'IBM Plex Mono',Consolas,monospace;font-size:12px;color:#c9d7ff}
.tag{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#0b1220}
.note{background:#121c30;border-left:4px solid #e5b800;padding:10px 14px;border-radius:6px;color:#c8d3e0}
.small{color:#8ea0b8;font-size:12px}pre{background:#0f172a;border:1px solid #22304a;padding:10px;border-radius:8px;overflow:auto;font-size:12px}
"""


def _esc(x) -> str:
    return html.escape("" if x is None else str(x))


def _tag(tier: str) -> str:
    return f'<span class="tag" style="background:{TIER_COLOR.get(tier, "#8ea0b8")}">{_esc(TIER_LABEL.get(tier, tier))}</span>'


def scatter_svg(assets: list[CryptoAsset], w: int = 720, h: int = 420) -> str:
    pad = 48
    pts = []
    maxp = max([a.risk.priority for a in assets if a.risk] + [1.0])
    for a in assets:
        if not a.risk or not a.agility:
            continue
        x = pad + (100 - a.agility.total) / 100.0 * (w - 2 * pad)          # harder to change ->
        y = h - pad - (a.risk.priority / maxp) * (h - 2 * pad)              # higher risk ^
        pts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{TIER_COLOR.get(a.risk.tier, "#8ea0b8")}" opacity=".9">'
                   f'<title>{_esc(a.name)} [{_esc(a.component)}] tier={_esc(a.risk.tier)} priority={a.risk.priority:g} agility={a.agility.total}</title></circle>')
    midx, midy = pad + (w - 2 * pad) / 2, pad + (h - 2 * pad) / 2
    return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="risk versus migration difficulty">'
            f'<rect x="{pad}" y="{pad}" width="{w - 2 * pad}" height="{h - 2 * pad}" fill="#121c30" stroke="#22304a"/>'
            f'<line x1="{midx}" y1="{pad}" x2="{midx}" y2="{h - pad}" stroke="#22304a" stroke-dasharray="4 4"/>'
            f'<line x1="{pad}" y1="{midy}" x2="{w - pad}" y2="{midy}" stroke="#22304a" stroke-dasharray="4 4"/>'
            f'<text x="{pad + 8}" y="{pad + 18}" fill="#8ea0b8" font-size="12">DO THIS NOW (risky, easy)</text>'
            f'<text x="{midx + 8}" y="{pad + 18}" fill="#8ea0b8" font-size="12">START PLANNING NOW (risky, hard)</text>'
            f'<text x="{pad + 8}" y="{h - pad - 8}" fill="#8ea0b8" font-size="12">cheap wins</text>'
            f'<text x="{midx + 8}" y="{h - pad - 8}" fill="#8ea0b8" font-size="12">leave it</text>'
            f'<text x="{w / 2}" y="{h - 12}" fill="#8ea0b8" font-size="12" text-anchor="middle">migration difficulty (agility 100 -> 0) &#8594;</text>'
            f'<text x="14" y="{h / 2}" fill="#8ea0b8" font-size="12" transform="rotate(-90 14 {h / 2})" text-anchor="middle">quantum risk priority &#8593;</text>'
            + "".join(pts) + "</svg>")


def _asset_row(a: CryptoAsset) -> str:
    r, rec, e = a.risk, a.recommendation, (a.evidence[0] if a.evidence else None)
    ks = a.key_size or (a.props or {}).get("key_size")
    where = f"{_esc(e.location)}:{e.line}" if e and e.line else (_esc(e.location) if e else "")
    return ("<tr>"
            f"<td>{_tag(r.tier) if r else ''}</td><td><b>{_esc(a.name)}</b>{('-' + str(ks)) if ks and a.asset_type == 'algorithm' and '-' not in a.name else ''}"
            f"<div class='small'>{_esc(a.asset_type)} / {_esc(a.primitive or '')}</div></td>"
            f"<td>{_esc(a.component)}</td><td><code>{where}</code></td>"
            f"<td>{_esc(r.quantum_class) if r else ''}<div class='small'>{'HNDL' if r and r.hndl_applicable else ''}</div></td>"
            f"<td>{a.lifetime_years:g}y / {r.y:g}y / {r.z:g}y</td>" if r and a.lifetime_years is not None else "<td></td>"
            ) + (f"<td>{a.agility.total if a.agility else ''}</td>"
                 f"<td>{_esc(rec.target) if rec and rec.target else '-'}{' (hybrid)' if rec and rec.hybrid else ''}"
                 f"<div class='small'>{_esc(rec.effort_weeks) + ' wk' if rec and rec.effort_weeks else ''}</div></td>"
                 f"<td>{_esc(a.confidence)}<div class='small'>{_esc(a.context.get('usage', ''))}</div></td></tr>")


def render(result: ScanResult) -> str:
    assets = result.assets
    tiers = {t: [a for a in assets if a.risk and a.risk.tier == t] for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE")}
    z = result.params.z_year
    plan = result.plan or {}
    certin = [a.certin for a in assets if a.certin and a.certin.get("pct") is not None]
    certin_pct = round(sum(c.get("pct", 0) for c in certin) / len(certin), 1) if certin else None
    profile = result.params.profile
    dst = {"cii": (2027, 2028, 2029), "enterprise": (2028, 2030, 2033)}.get(profile, (2028, 2030, 2033))
    violations: dict[str, int] = {}
    for a in assets:
        for o in (a.risk.overlays if a.risk else []):
            if o.get("status") == "violation":
                violations[o["framework"]] = violations.get(o["framework"], 0) + 1

    parts = [f"<!doctype html><html><head><meta charset='utf-8'><title>ECDAT report - {_esc(result.name)}</title><style>{CSS}</style></head><body>"]
    parts.append(f"<h1>ECDAT cryptographic risk report</h1><div class='sub'>{_esc(result.name)} &middot; {_esc(result.timestamp[:19])} &middot; ECDAT {__version__} "
                 f"&middot; quantum horizon Z = <b>{z}</b> ({z - result.params.now_year} years, user-set) &middot; profile {_esc(profile.upper())}</div>")
    parts.append("<div class='grid'>" + "".join(
        f"<div class='tile'><div class='n' style='color:{TIER_COLOR[t]}'>{len(tiers[t])}</div><div class='l'>{TIER_LABEL[t]}</div></div>"
        for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE")) + "</div>")
    parts.append("<div class='grid' style='margin-top:12px'>"
                 f"<div class='tile'><div class='n'>{len(assets)}</div><div class='l'>crypto assets</div></div>"
                 f"<div class='tile'><div class='n'>{sum(1 for a in assets if a.risk and a.risk.hndl_applicable)}</div><div class='l'>harvestable today (HNDL)</div></div>"
                 f"<div class='tile'><div class='n'>{_esc(certin_pct) + '%' if certin_pct is not None else 'n/a'}</div><div class='l'>CERT-In Table 9 completeness</div></div>"
                 f"<div class='tile'><div class='n'>{plan.get('covered_pct', 'n/a')}{'%' if plan else ''}</div><div class='l'>risk removed in budget</div></div></div>")

    parts.append("<h2>Where you stand: risk x migration difficulty</h2>" + scatter_svg(assets))

    parts.append(f"<h2>India milestones (DST / NQM, {_esc(profile.upper())})</h2><table><tr><th>Milestone</th><th>Year</th><th>Status</th></tr>"
                 f"<tr><td>M1 inventory + risk assessment + CBOM</td><td>{dst[0]}</td><td>{len(assets)} assets inventoried in CycloneDX 1.7</td></tr>"
                 f"<tr><td>M2 no new classical-only deployments</td><td>{dst[1]}</td><td>{sum(1 for a in assets if a.risk and a.risk.quantum_class in ('broken', 'legacy-broken') and a.context.get('usage') not in ('test', 'comment', 'non-security'))} classical-only assets would be blocked by the CI gate</td></tr>"
                 f"<tr><td>M3 quantum-safe-only trust chains</td><td>{dst[2]}</td><td>{len(tiers['EXPOSED']) + len(tiers['ACT_NOW'])} assets must migrate first</td></tr></table>")
    if violations:
        parts.append("<h3>Framework violations</h3><table><tr><th>Framework</th><th>Violations</th></tr>" +
                     "".join(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in sorted(violations.items())) + "</table>")

    for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE"):
        rows = tiers[t]
        parts.append(f"<h2>{_tag(t)} &nbsp; {len(rows)}</h2>")
        if t == "EXPOSED":
            parts.append("<div class='note'>Data protected by these assets can be recorded today and decrypted once a CRQC exists: "
                         "its confidentiality lifetime plus the migration time exceeds the quantum horizon. Migration alone does not "
                         "save data already captured. Consider re-keying, shortening retention, or accepting the loss.</div>")
        if rows:
            parts.append("<table><tr><th>Tier</th><th>Asset</th><th>Component</th><th>Where</th><th>Class</th><th>X / Y / Z</th><th>Agility</th><th>Recommendation</th><th>Confidence</th></tr>"
                         + "".join(_asset_row(a) for a in sorted(rows, key=lambda a: -(a.risk.priority if a.risk else 0))) + "</table>")
        else:
            parts.append("<p class='small'>none</p>")

    if plan:
        parts.append(f"<h2>Migration plan: {plan.get('engineers')} engineers x {plan.get('months')} months = {plan.get('capacity_weeks')} engineer-weeks</h2>")
        parts.append(f"<p>{plan.get('used_weeks')} weeks used, <b>{plan.get('covered_pct')}%</b> of quantum risk removed; {len(plan.get('uncovered', []))} item(s) do not fit "
                     f"({plan.get('exposed_remaining', 0)} still EXPOSED).</p><table><tr><th>#</th><th>Asset</th><th>Component</th><th>Tier</th><th>Target</th><th>Effort (wk)</th><th>Cum. weeks</th><th>Cum. risk %</th></tr>"
                     + "".join(f"<tr><td>{i + 1}</td><td>{_esc(it['name'])}</td><td>{_esc(it['component'])}</td><td>{_tag(it['tier'])}</td><td>{_esc(it.get('target') or '-')}</td>"
                               f"<td>{it['effort_weeks']}</td><td>{it['cumulative_weeks']}</td><td>{it['cumulative_risk_pct']}</td></tr>" for i, it in enumerate(plan.get("items", [])))
                     + "</table>")

    patches = [(a, p) for a in assets if a.recommendation for p in (a.recommendation.patches or [])]
    if patches:
        parts.append(f"<h2>Patch suggestions ({len(patches)})</h2><p class='small'>Suggestions with evidence; never applied automatically.</p>")
        for a, p in patches[:20]:
            parts.append(f"<h3>{_esc(p['title'])} <span class='small'>{_esc(p['file'])}</span></h3><pre>{_esc(p['unified_diff'])}</pre><p class='small'>{_esc(p['note'])}</p>")

    if certin:
        missing: dict[str, int] = {}
        for c in certin:
            for m in c.get("missing", []):
                missing[m] = missing.get(m, 0) + 1
        parts.append(f"<h2>CERT-In v2.0 Table 9 completeness: {certin_pct}%</h2>")
        if missing:
            parts.append("<table><tr><th>Missing element</th><th>Assets</th></tr>" + "".join(f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>" for k, v in sorted(missing.items(), key=lambda kv: -kv[1])[:15]) + "</table>")

    parts.append("<h2>Methodology and honesty notes</h2><ul>"
                 f"<li><b>Z is an assumption.</b> The quantum horizon is set to {z}. The Global Risk Institute 2025 expert survey puts a CRQC at 28-49% likely within 10 years and 51-70% within 15; presets: aggressive 2032, NIST-disallow 2035, GRI-median 2041.</li>"
                 "<li><b>Mosca's inequality (X + Y &gt; Z) is applied only to confidentiality primitives</b> (key exchange, KEMs, ciphers). Signatures, hashes and MACs cannot be harvested; they are scored against regulatory deadlines instead.</li>"
                 "<li><b>Binary findings are best-effort.</b> Constants and version strings prove presence, not use; they are capped at medium confidence.</li>"
                 "<li><b>Every finding carries confidence and evidence</b> (collector, file:line, snippet). Regex-only and comment matches are low confidence; matches corroborated by two engines are promoted.</li>"
                 "<li><b>Lifetimes and criticality are defaults</b> inferred from names and paths unless the configuration sets them; edit them and re-run.</li>"
                 "<li><b>Patches are suggestions</b>, never applied: LLM- and template-generated PQC code drifts insecure without review.</li>"
                 "</ul>")
    parts.append("</body></html>")
    return "".join(parts)


def write(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(render(result), encoding="utf-8")
    return p
