"""Build the public evidence site (GitHub Pages) from real result files. Nothing is pushed.

    python scripts/build_site.py [--repo-url URL] [--video-url URL] [--team NAME]

out/site/
  index.html                 evidence hub (what the slide QR opens)
  atlas/                     CBOM Atlas: index.html, atlas.json, r/<slug>/{cbom.json, .sig, report.html, vex.json}
  snapshot/                  India quantum-readiness snapshot: sector aggregates only (never host names)
  dashboard/                 the real ECDAT dashboard in static mode + precomputed scans
  ecdat-mldsa65.pub          the public key every atlas CBOM verifies against
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out"
SITE = OUT / "site"
PY = sys.executable
Z_PRESETS = [2032, 2035, 2041]
PROFILES = ["cii", "enterprise"]
DASHBOARD_SCANS = [("real-world-0918", "Real world: pyjwt, node-jsonwebtoken, paramiko + 4 live servers"),
                   ("zoo-0918", "Crypto zoo: our planted-answer test estate (containers, binaries, pcap, certs)")]
EXPORTS = {"cbom": "cbom.json", "vex": "vex.json", "sarif": "findings.sarif", "csv": "assets.csv",
           "report.html": "report.html", "report.pdf": "report.pdf"}

# Colours validated with the dataviz skill's validate_palette.js (light + dark, all checks pass; the light
# amber is below 3:1 so every bar carries a visible value label and the page has a table view).
CSS = """
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
:root{--paper:#fbfaf7;--panel:#ffffff;--ink:#12212e;--ink2:#41505d;--muted:#6f7c88;--rule:#e3e0d9;
--rule2:#cfcabf;--india:#eda100;--ref:#1f5fae;--accent:#a87400;--exposed:#b8322f;--safe:#256f4a;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--paper:#14181b;--panel:#191e22;--ink:#eef1f2;--ink2:#b9c2c8;
--muted:#8a949c;--rule:#2a3136;--rule2:#3b444b;--india:#eda100;--ref:#6ba8f0;--accent:#e9b44c;
--exposed:#e5736f;--safe:#5cbe8d;color-scheme:dark}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);
font:16px/1.62 "IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
-webkit-font-smoothing:antialiased;font-variant-numeric:tabular-nums}
main{max-width:1180px;margin:0 auto;padding:56px 28px 80px}
@media(max-width:640px){main{padding:34px 18px 56px}}
a{color:var(--ref);text-decoration:none;border-bottom:1px solid rgba(31,95,174,.3)}
a:hover{border-bottom-color:currentColor}
a:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
.kicker{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:11.5px;letter-spacing:.18em;
text-transform:uppercase;color:var(--muted);margin:0 0 14px}
h1{font-size:40px;line-height:1.08;letter-spacing:-.02em;font-weight:600;margin:0}
h2{font-size:15px;letter-spacing:.14em;text-transform:uppercase;font-family:"IBM Plex Mono",monospace;
font-weight:500;color:var(--muted);margin:52px 0 14px;display:flex;align-items:center;gap:14px}
h2::after{content:"";flex:1;height:1px;background:var(--rule)}
h3{font-size:17px;margin:26px 0 6px;font-weight:600}
.lede{font-size:19px;line-height:1.5;color:var(--ink2);margin:14px 0 0;max-width:62ch}
.rule{width:64px;height:3px;background:var(--india);border-radius:2px;margin:26px 0 0}
p{max-width:74ch}
.sub{color:var(--ink2);margin:6px 0 0;max-width:74ch}
.muted{color:var(--muted)}.small{font-size:13.5px}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace}
/* the three artefacts, as a record rather than as cards */
.artefacts{border-top:1px solid var(--rule)}
.artefact{position:relative;display:flex;gap:32px;align-items:flex-start;justify-content:space-between;
padding:18px 14px;margin:0 -14px;border-bottom:1px solid var(--rule);border-radius:8px;cursor:pointer;
transition:background .12s ease}
/* the whole row is the tap target: the title's link is stretched over it, so the accessible
   name stays the title and keyboard focus still lands on one link per row */
.artefact .n a::after{content:"";position:absolute;inset:0;border-radius:8px}
.artefact:hover{background:rgba(237,161,0,.07)}
.artefact:hover .n a{border-bottom-color:currentColor}
.artefact:focus-within{background:rgba(237,161,0,.07);outline:2px solid var(--accent);outline-offset:-2px}
.artefact:focus-within .n a:focus-visible{outline:none}
.artefact .t{flex:1;min-width:0}
.artefact .n{font-size:19px;font-weight:600;letter-spacing:-.01em;margin-bottom:5px}
.artefact .n a{border-bottom:1px solid transparent}
.artefact .d{color:var(--ink2);font-size:14.5px;max-width:62ch}
.artefact .go{display:block;margin-top:8px;font-family:"IBM Plex Mono",monospace;font-size:11px;
letter-spacing:.14em;text-transform:uppercase;color:var(--muted);opacity:0;transition:opacity .12s ease}
.artefact:hover .go,.artefact:focus-within .go{opacity:1}
.artefact .f{flex:none;width:126px;text-align:right;font-family:"IBM Plex Mono",monospace;color:var(--muted);
font-size:12px;line-height:1.45;white-space:nowrap}
.artefact .f b{display:block;font-size:23px;font-weight:600;color:var(--ink);letter-spacing:-.02em;margin-bottom:2px}
/* stat line, used by the atlas */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:2px 28px;margin:18px 0 8px}
.tile{padding:12px 0 2px;border-top:2px solid var(--rule2)}
.tile .v{font-size:30px;font-weight:600;letter-spacing:-.02em;line-height:1.1}
.tile .l{color:var(--muted);font-size:12.5px;line-height:1.35;margin-top:4px;max-width:26ch}
pre{background:var(--panel);border:1px solid var(--rule);border-left:3px solid var(--india);
border-radius:0 6px 6px 0;padding:14px 16px;overflow:auto;font-size:13.5px;line-height:1.65;
font-family:"IBM Plex Mono",ui-monospace,monospace}
code{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:.92em}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin-top:8px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--rule);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;
font-family:"IBM Plex Mono",monospace;cursor:pointer;line-height:1.35;vertical-align:bottom;
border-bottom:1px solid var(--rule2)}
th:first-child,td:first-child{min-width:150px}
td:last-child,td:nth-child(2){white-space:nowrap}
.scroll{overflow-x:auto;margin-top:8px}
tbody tr:hover{background:rgba(237,161,0,.05)}
td.num,th.num{text-align:right;font-family:"IBM Plex Mono",monospace}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}
.filters button{background:transparent;border:1px solid var(--rule2);border-radius:999px;padding:4px 13px;
color:var(--ink2);cursor:pointer;font:inherit;font-size:13px}
.filters button:hover{border-color:var(--accent)}
.filters button.on{border-color:var(--accent);color:var(--accent);background:rgba(237,161,0,.08)}
.note{border-left:2px solid var(--rule2);padding:4px 0 4px 16px;color:var(--muted);font-size:13.5px;max-width:78ch}
.kv{font-size:13.5px;color:var(--ink2)}
.kv b{font-weight:500;color:var(--ink)}
footer{margin-top:64px;padding-top:16px;border-top:1px solid var(--rule);color:var(--muted);font-size:12.5px;
display:flex;gap:16px;flex-wrap:wrap;justify-content:space-between}
"""


def page(title: str, body: str, depth: int = 0) -> str:
    up = "../" * depth
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><link rel='icon' href='data:,'><style>{CSS}</style></head><body><main>{body}"
            f"<footer><span>ECDAT \u00b7 Smart India Hackathon 2026 \u00b7 problem statement 26164 (NTRO)</span>"
            f"<span><a href='{up}index.html'>evidence hub</a></span></footer></main></body></html>")


def _run(args: list[str]) -> None:
    proc = subprocess.run([PY, "-m", "ecdat.cli", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise SystemExit(f"ecdat {' '.join(args)} failed:\n{proc.stderr[-2000:]}")


# ------------------------------------------------------------------------------------------ dashboard
def build_dashboard() -> None:
    dest = SITE / "dashboard"
    shutil.copytree(ROOT / "web" / "dist", dest)
    static = dest / "static"
    static.mkdir(parents=True, exist_ok=True)
    scans = []
    for scan_dir, label in DASHBOARD_SCANS:
        src = OUT / scan_dir / "result.json"
        base = json.loads(src.read_text(encoding="utf-8"))
        eng, mon = base["params"]["engineers"], base["params"]["months"]
        variants = []
        for prof in PROFILES:
            for z in Z_PRESETS:
                tmp = OUT / "_site_tmp" / f"{scan_dir}-{z}-{prof}"
                _run(["recompute", str(src), "--z-year", str(z), "--profile", prof, "-o", str(tmp)])
                name = f"{scan_dir}-{z}-{prof}.json"
                shutil.copy(tmp / "result.json", static / name)
                variants.append({"z_year": z, "profile": prof, "engineers": eng, "months": mon, "file": name})
        exp = static / "exports" / scan_dir
        exp.mkdir(parents=True)
        exports = {}
        for kind, fname in EXPORTS.items():
            if (OUT / scan_dir / fname).exists():
                shutil.copy(OUT / scan_dir / fname, exp / fname)
                exports[kind] = f"exports/{scan_dir}/{fname}"
        default = f"{scan_dir}-2041-cii.json"
        scans.append({"id": base["id"], "name": label, "timestamp": base.get("timestamp", ""), "default": default,
                      "variants": variants, "exports": exports})
    (static / "index.json").write_text(json.dumps({"scans": scans}, indent=1), encoding="utf-8")
    shutil.rmtree(OUT / "_site_tmp", ignore_errors=True)


# ------------------------------------------------------------------------------------------ atlas
def build_atlas() -> dict:
    atlas = json.loads((OUT / "atlas" / "atlas.json").read_text(encoding="utf-8"))
    dest = SITE / "atlas"
    for r in atlas["repos"]:
        # atlas.json is written by the run that filled scans/; the runner rotates that directory to
        # scans_prev/ when a later partial re-scan starts, so publish whichever one holds this run's
        # artefacts - never a mix, or a row's numbers would disagree with the file under it.
        src = OUT / "atlas" / "scans" / r["slug"]
        if not (src / "cbom.json").exists():
            src = OUT / "atlas" / "scans_prev" / r["slug"]
        d = dest / "r" / r["slug"]
        d.mkdir(parents=True, exist_ok=True)
        for f in ("cbom.json", "cbom.json.mldsa65.sig", "report.html", "vex.json", "summary.md"):
            if (src / f).exists():
                shutil.copy(src / f, d / f)
    public = {k: atlas[k] for k in ("overall", "by_category", "repos", "params")}
    (dest / "atlas.json").write_text(json.dumps(public, indent=1), encoding="utf-8")
    audit = OUT / "atlas" / "audit.json"
    au = json.loads(audit.read_text(encoding="utf-8")) if audit.exists() else None
    o = atlas["overall"]
    tiles = [(o["repos"], "public repositories, one signed CBOM each"), (f"{o['assets']:,}", "cryptographic assets inventoried"),
             (f"{o['scan_seconds_median']:.0f} s", "median scan time per repository"),
             (f"{min(o['cbom_valid_pct'], o['signed_pct']):.0f}%", "CycloneDX 1.7 schema-valid and ML-DSA-65 signed")]
    if au:
        tiles.append((f"{100 * au['correct'] / au['n']:.0f}%", f"precision on a hand-audited random sample of {au['n']} flagged findings"))
    tile_html = "".join(f"<div class='tile'><div class='v'>{html.escape(str(v))}</div><div class='l'>{html.escape(l)}</div></div>" for v, l in tiles)
    cats = "<table><thead><tr><th>category</th><th class='num'>repos</th><th class='num'>quantum-vulnerable crypto in production</th>"            "<th class='num'>crypto broken today</th><th class='num'>already use post-quantum</th><th class='num'>CERT-In avg</th></tr></thead><tbody>" + "".join(
        f"<tr><td>{html.escape(c['label'])}</td><td class='num'>{c['repos']}</td><td class='num'>{c['repos_with_shor_broken_pct']:.0f}%</td>"
        f"<td class='num'>{c['repos_with_legacy_broken_pct']:.0f}%</td><td class='num'>{c['repos_with_pqc_pct']:.0f}%</td><td class='num'>{c['certin_avg_pct']:.0f}%</td></tr>"
        for c in atlas["by_category"].values() if c["repos"]) + "</tbody></table>"
    body = f"""
<h1>CBOM Atlas</h1>
<p class='sub'>We scanned {o['repos']} public codebases with our prototype on 18 Sep 2026. Every row links to the CycloneDX 1.7
Cryptographic Bill of Materials we produced, signed with ML-DSA-65 (FIPS 204), together with its human-readable report and VEX file.</p>
<div class='tiles'>{tile_html}</div>
<h2>By category</h2>{cats}
<h2>Every repository</h2>
<div class='filters' id='filters'></div>
<table id='t'><thead><tr><th data-k='repo'>repository</th><th data-k='category'>category</th><th data-k='data_class'>data kept for</th>
<th class='num' data-k='observed'>observed</th><th class='num' data-k='EXPOSED'>exposed</th><th class='num' data-k='ACT_NOW'>act now</th>
<th class='num' data-k='MONITOR'>monitor</th><th data-k='vuln'>quantum-vulnerable in production</th><th data-k='pqc'>post-quantum</th>
<th class='num' data-k='certin_pct'>CERT-In</th><th>files</th></tr></thead><tbody></tbody></table>
<h2>How to check our work</h2>
<pre>git clone &lt;ecdat repo&gt; &amp;&amp; cd ecdat &amp;&amp; pip install -e .
ecdat verify r/&lt;repo&gt;/cbom.json --pubkey ../ecdat-mldsa65.pub</pre>
<p class='note'>"Observed" means we found it in the project's own code, configuration, certificates or binaries. Algorithms a dependency merely
<i>can</i> provide we list in the CBOM as dependency inventory ({o['library_capability_only']:,} of them) and never count as use.
"Data kept for" is the assumption that drives Mosca's rule for that repository; change it and the tiers change. Quantum-vulnerable
algorithms such as RSA are today's global default, not a flaw in any one project. Maintainers who want a row changed or removed can open
an issue.</p>
<script>
const LIFE={{session:'hours (session)',pii:'7 y (personal data)',financial:'10 y (financial)',identity:'20 y (identity)',health:'25 y (health)',defence:'30 y (defence)',generic:'5 y (generic)'}};
let rows=[],cat='all',key='category',asc=true;
fetch('atlas.json').then(r=>r.json()).then(d=>{{rows=d.repos.map(r=>({{...r,...r.tiers,vuln:[...r.shor_broken_in_production,...r.legacy_broken_in_production].join(', '),pqc:r.pqc_present.join(', ')}}));
const cats=Object.entries(d.by_category).filter(([k,v])=>v.repos);const f=document.getElementById('filters');
[['all','all']].concat(cats.map(([k,v])=>[k,v.label])).forEach(([k,l])=>{{const b=document.createElement('button');b.textContent=l;b.onclick=()=>{{cat=k;draw()}};b.dataset.k=k;f.appendChild(b)}});draw()}});
document.querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{{const k=th.dataset.k;asc=key===k?!asc:true;key=k;draw()}});
function esc(s){{return String(s??'').replace(/[&<>]/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;'}}[c]))}}
function draw(){{document.querySelectorAll('#filters button').forEach(b=>b.classList.toggle('on',b.dataset.k===cat));
const v=rows.filter(r=>cat==='all'||r.category===cat).sort((a,b)=>{{const x=a[key],y=b[key];return (x>y?1:x<y?-1:0)*(asc?1:-1)}});
document.querySelector('#t tbody').innerHTML=v.map(r=>`<tr><td><a href="${{r.url}}">${{esc(r.repo)}}</a><div class='muted small'>${{esc(r.language||'')}}</div></td>
<td class='small'>${{esc(r.category)}}</td><td class='small'>${{esc(LIFE[r.data_class]||r.data_class)}}</td><td class='num'>${{r.observed}}</td>
<td class='num'>${{r.EXPOSED}}</td><td class='num'>${{r.ACT_NOW}}</td><td class='num'>${{r.MONITOR}}</td><td class='small'>${{esc(r.vuln)||'<span class=muted>none</span>'}}</td>
<td class='small'>${{esc(r.pqc)||'<span class=muted>none</span>'}}</td><td class='num'>${{(r.certin_pct??0).toFixed(0)}}%</td>
<td class='small'><a href="r/${{r.slug}}/cbom.json">CBOM</a> · <a href="r/${{r.slug}}/cbom.json.mldsa65.sig">sig</a> · <a href="r/${{r.slug}}/report.html">report</a> · <a href="r/${{r.slug}}/vex.json">VEX</a></td></tr>`).join('')}}
</script>"""
    (dest / "index.html").write_text(page("ECDAT · CBOM Atlas", body, 1), encoding="utf-8")
    return atlas


# ------------------------------------------------------------------------------------------ snapshot
ORDER = ["Global reference", "Banking, financial services & insurance", "Power & energy", "Government (central)", "Transport",
         "Health", "Telecom", "Strategic & public enterprises"]


def snapshot_svg(sectors: dict, india: dict, width: int = 900) -> str:
    rows = [(s, sectors[s]) for s in ORDER if s in sectors] + [("India, all 7 sectors", {**india, "hosts_probed": india["reachable"]})]
    label_w, pad_r, bar_h, gap = 300, 70, 22, 14
    plot_w = width - label_w - pad_r
    height = 40 + len(rows) * (bar_h + gap) + 20
    parts = [f"<svg viewBox='0 0 {width} {height}' width='100%' role='img' aria-label='Share of sites negotiating hybrid post-quantum key exchange, by sector' "
             f"xmlns='http://www.w3.org/2000/svg' style='font-family:IBM Plex Sans,Inter,system-ui,sans-serif'>"]
    for pct in (0, 25, 50, 75, 100):
        x = label_w + plot_w * pct / 100
        parts.append(f"<line x1='{x:.1f}' y1='28' x2='{x:.1f}' y2='{height - 16}' stroke='var(--rule)' stroke-width='1'/>"
                     f"<text x='{x:.1f}' y='20' font-size='12' fill='var(--muted)' text-anchor='middle'>{pct}%</text>")
    for i, (name, v) in enumerate(rows):
        y = 36 + i * (bar_h + gap)
        pct = v["pq_hybrid_kex_pct"]
        w = max(plot_w * pct / 100, 0)
        colour = "var(--ref)" if name == "Global reference" else "var(--india)"
        bold = " font-weight='600'" if name.startswith(("India", "Global")) else ""
        n = v.get("reachable", 0)
        tip = f"{name}: {pct}% of {n} reachable sites negotiate hybrid post-quantum key exchange"
        parts.append(f"<g><title>{html.escape(tip)}</title>"
                     f"<text x='{label_w - 12}' y='{y + bar_h * 0.72:.1f}' font-size='14' fill='var(--ink)' text-anchor='end'{bold}>{html.escape(name)}</text>")
        if w > 0:
            r = min(4, w / 2)
            # square at the baseline, 4px rounded data-end
            parts.append(f"<path d='M{label_w},{y} h{w - r:.1f} a{r},{r} 0 0 1 {r},{r} v{bar_h - 2 * r} a{r},{r} 0 0 1 -{r},{r} h-{w - r:.1f} z' fill='{colour}'/>")
        else:
            parts.append(f"<line x1='{label_w}' y1='{y}' x2='{label_w}' y2='{y + bar_h}' stroke='{colour}' stroke-width='2'/>")
        parts.append(f"<rect x='{label_w}' y='{y - gap / 2}' width='{plot_w}' height='{bar_h + gap}' fill='transparent'/>"
                     f"<text x='{label_w + w + 8:.1f}' y='{y + bar_h * 0.72:.1f}' font-size='14' fill='var(--ink)'{bold}>{pct:.1f}%</text>"
                     f"<text x='{width - 4}' y='{y + bar_h * 0.72:.1f}' font-size='12' fill='var(--muted)' text-anchor='end'>n={n}</text></g>")
    parts.append("</svg>")
    return "".join(parts)


def build_snapshot() -> dict:
    s = json.loads((OUT / "survey" / "survey.json").read_text(encoding="utf-8"))
    sectors = {k: v for k, v in s["sectors"].items() if not k.startswith("_")}
    india = s["sectors"]["_india_all"]
    svg = snapshot_svg(sectors, india)
    table = "".join(f"<tr><td>{html.escape(k)}</td><td class='num'>{v['reachable']}/{v['hosts_probed']}</td><td class='num'>{v['pq_hybrid_kex_pct']}%</td>"
                    f"<td class='num'>{v['tls13_pct']}%</td><td class='num'>{v['rsa_cert_pct']}%</td><td class='num'>{v['ecdsa_cert_pct']}%</td></tr>"
                    for k, v in sectors.items())
    body = f"""
<h1>India quantum-readiness snapshot</h1>
<p class='sub'>We asked which public sites already negotiate hybrid post-quantum key exchange (X25519MLKEM768). We probed {india['reachable']} Indian
public sites across NCIIPC's seven critical sectors, plus 25 global reference sites as a control, on
{html.escape(s['taken_utc'].replace('T', ' ').replace('+00:00', ''))} UTC using our own protocol scanner.</p>
<p class='small'><span style='color:var(--india)'>■</span> Indian sector &nbsp; <span style='color:var(--ref)'>■</span> global reference</p>
{svg}
<div class='tiles'><div class='tile'><div class='v'>{india['pq_hybrid_kex_pct']}%</div><div class='l'>of the Indian sites we probed use post-quantum key exchange (our global reference: {sectors['Global reference']['pq_hybrid_kex_pct']}%)</div></div>
<div class='tile'><div class='v'>{india['rsa_cert_pct']:.0f}%</div><div class='l'>of the Indian sites we probed present an RSA certificate</div></div>
<div class='tile'><div class='v'>0%</div><div class='l'>post-quantum certificates in anything we probed: no public CA issues them yet</div></div>
<div class='tile'><div class='v'>22 / 25</div><div class='l'>Indian sites that pass sit behind a CDN that enabled it for them</div></div></div>
<details><summary>Table view</summary><table><thead><tr><th>sector</th><th class='num'>reachable / probed</th><th class='num'>hybrid PQ key exchange</th>
<th class='num'>TLS 1.3</th><th class='num'>RSA leaf cert</th><th class='num'>ECDSA leaf cert</th></tr></thead><tbody>{table}</tbody></table></details>
<h2>Method</h2>
<p class='note'>We make two connections per site, exactly what a browser does on a visit: one TLS 1.3 ClientHello offering X25519MLKEM768 first
(which key-exchange group does the server pick?) and one normal handshake (version, cipher suite, leaf certificate). We do not crawl, probe for
vulnerabilities or authenticate. We publish sector totals only and keep the list of sites to ourselves. A result reflects a site's public edge
(often a CDN), not necessarily its internal systems. This is our snapshot, not a ranking.</p>"""
    dest = SITE / "snapshot"
    dest.mkdir(parents=True)
    (dest / "index.html").write_text(page("ECDAT · India quantum-readiness snapshot", body, 1), encoding="utf-8")
    # bare chart for the slide export (no page chrome): screenshot #chart
    (dest / "chart.html").write_text(
        f"<!doctype html><html><head><meta charset='utf-8'><link rel='icon' href='data:,'><style>{CSS}</style></head><body>"
        f"<div id='chart' style='padding:16px 20px;background:var(--surface)'><p class='small' style='margin:0 0 4px'>"
        f"<span style='color:var(--india)'>■</span> Indian sector &nbsp; <span style='color:var(--ref)'>■</span> global reference</p>{svg}</div>"
        f"</body></html>", encoding="utf-8")
    (dest / "survey.json").write_text(json.dumps({"taken_utc": s["taken_utc"], "sectors": s["sectors"]}, indent=1), encoding="utf-8")
    return s


# ------------------------------------------------------------------------------------------ hub
def build_hub(atlas: dict, survey: dict, repo_url: str, video_url: str, team: str, pub_fpr: str, tests: str) -> None:
    o = atlas["overall"]
    india = survey["sectors"]["_india_all"]
    glob = survey["sectors"]["Global reference"]
    scanned = atlas.get("params", {}).get("scanned_on", "18 Sep 2026")

    rows = [("CBOM Atlas", "atlas/index.html",
             f"We pointed our prototype at {o['repos']} public codebases, including India's open digital public "
             f"infrastructure. Every inventory we produced is a CycloneDX 1.7 CBOM signed with ML-DSA-65, published "
             f"here with its report and VEX file.",
             f"{o['repos']}", "repositories", scanned),
            ("India quantum-readiness snapshot", "snapshot/index.html",
             f"We probed {india['reachable']} public sites across NCIIPC's seven critical sectors. "
             f"{india['pq_hybrid_kex_pct']}% negotiate post-quantum key exchange, against {glob['pq_hybrid_kex_pct']}% of the "
             f"global reference sites we used as a control. We publish sector totals only \u2014 we name no site.",
             f"{india['reachable']}", "sites", "18 Sep 2026"),
            ("The dashboard, on real scans", "dashboard/index.html",
             "Our dashboard, running on the scans above. Move the quantum-year slider, filter by tier, open any asset "
             "and read the evidence our scanners produced for it.",
             "2", "scans", "live")]
    if video_url:
        rows.append(("Three-minute walkthrough", video_url,
                     "We scan, reconcile, score, plan, export and verify \u2014 end to end.", "3", "minutes", ""))

    items = "".join(
        f"<div class='artefact'><div class='t'><div class='n'><a href='{html.escape(href)}'>{html.escape(name)}</a></div>"
        f"<div class='d'>{desc}</div></div>"
        f"<div class='f'><b>{html.escape(fig)}</b>{html.escape(unit)}<br>{html.escape(when)}"
        f"<span class='go'>open &rarr;</span></div></div>"
        for name, href, desc, fig, unit, when in rows)

    team_bit = (" · " + html.escape(team)) if team else ""
    body = f"""
<p class='kicker'>Smart India Hackathon 2026 · PS 26164 · NTRO{team_bit}</p>
<h1>ECDAT</h1>
<p class='lede'>We built ECDAT to find every piece of cryptography an organisation runs, show which of it a quantum
computer will break and when that stops being theoretical, then plan the fix under a real budget.</p>
<div class='rule'></div>

<h2>What we built, and what we measured with it</h2>
<div class='artefacts'>{items}</div>

<h2>Check our work</h2>
<p class='sub'>We sign every CBOM we publish with ML-DSA-65 (FIPS 204). Download one, download our public key and
check it offline \u2014 we are not asking you to take our numbers on trust.</p>
<pre>git clone {html.escape(repo_url)} &amp;&amp; cd ecdat &amp;&amp; pip install -e .
curl -O https://sarthakshrivastav-a.github.io/ecdat/ecdat-mldsa65.pub
ecdat verify cbom.json --pubkey ecdat-mldsa65.pub</pre>
<p class='kv small'>Public key <a href='ecdat-mldsa65.pub'>ecdat-mldsa65.pub</a>, SHA-256
<span class='mono'>{pub_fpr}</span><br>
Our source <a href='{html.escape(repo_url)}'>{html.escape(repo_url.replace("https://", ""))}</a>,
<b>{tests}</b> automated tests, runs fully offline.</p>

<h2>How to read our numbers</h2>
<p class='note'>We scanned each repository's default branch as we downloaded it on {html.escape(scanned)}. <b>Observed</b> means we found it in
the project's own code, configuration, certificates or binaries; an algorithm a dependency merely <em>could</em> provide we list
separately and never count as use. For the snapshot we make two browser-equivalent connections per site and publish only sector
totals. Quantum-year <b>Z</b> is an assumption you set, not a forecast we are making.</p>"""
    (SITE / "index.html").write_text(page("ECDAT \u00b7 evidence", body, 0), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    remote = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    ap.add_argument("--repo-url", default=remote.removesuffix(".git") or "https://github.com/<owner>/ecdat")
    ap.add_argument("--video-url", default="")
    ap.add_argument("--team", default="")
    a = ap.parse_args()
    # empty the folder rather than deleting it (a local preview server may hold it as its working directory)
    SITE.mkdir(parents=True, exist_ok=True)
    for child in SITE.iterdir():
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    pub = OUT / "atlas" / "scans" / "keys" / "ecdat-mldsa65.pub"
    shutil.copy(pub, SITE / "ecdat-mldsa65.pub")
    fpr = hashlib.sha256(base64.b64decode(pub.read_text().strip())).hexdigest()
    col = subprocess.run([PY, "-m", "pytest", "--collect-only", "-q", "-p", "no:warnings"], cwd=ROOT, capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    tests = str(sum(int(line.rsplit(":", 1)[1]) for line in col.splitlines() if line.startswith("tests/") and line.rsplit(":", 1)[1].strip().isdigit()))
    atlas = build_atlas()
    survey = build_snapshot()
    build_dashboard()
    build_hub(atlas, survey, a.repo_url, a.video_url, a.team, fpr, tests)
    (SITE / ".nojekyll").write_text("", encoding="utf-8")
    size = sum(f.stat().st_size for f in SITE.rglob("*") if f.is_file())
    print(f"site built: {SITE}  ({size / 1e6:.1f} MB, {sum(1 for _ in SITE.rglob('*'))} files)")


if __name__ == "__main__":
    main()
