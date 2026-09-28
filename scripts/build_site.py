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
:root{--surface:#fcfcfb;--panel:#ffffff;--ink:#0b1b2b;--ink2:#52514e;--muted:#8a8984;--rule:#e6e5e1;
--india:#eda100;--ref:#2a78d6;--accent:#b37a00;--exposed:#e5484d;--safe:#30a46c;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--surface:#1a1a19;--panel:#222221;--ink:#f4f4f2;--ink2:#c3c2b7;
--muted:#8f8e88;--rule:#383835;--india:#c98500;--ref:#3987e5;--accent:#f5b301;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--surface);color:var(--ink);
font:15px/1.5 "IBM Plex Sans",Inter,system-ui,sans-serif}main{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
a{color:var(--ref)}h1{font-size:34px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 10px}
.sub{color:var(--ink2);margin:0 0 20px}.muted{color:var(--muted)}.small{font-size:13px}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace}.tag{display:inline-block;border:1px solid var(--rule);
border-radius:999px;padding:2px 10px;font-size:12px;color:var(--ink2);margin-right:6px}
.doors{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin:22px 0}
.door{display:block;background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:18px;
text-decoration:none;color:var(--ink)}.door:hover{border-color:var(--accent)}.door b{font-size:18px;display:block;margin-bottom:6px}
.door span{color:var(--ink2);font-size:14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:14px 0}
.tile{background:var(--panel);border:1px solid var(--rule);border-radius:10px;padding:14px}
.tile .v{font-size:34px;font-weight:600}.tile .l{color:var(--ink2);font-size:13px}
pre{background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:12px;overflow:auto;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--rule);
vertical-align:top}th{color:var(--ink2);font-weight:600;cursor:pointer;white-space:nowrap}td.num,th.num{text-align:right;
font-variant-numeric:tabular-nums}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
.filters button{background:var(--panel);border:1px solid var(--rule);border-radius:999px;padding:4px 12px;color:var(--ink);cursor:pointer}
.filters button.on{border-color:var(--accent);color:var(--accent)}
.note{border-left:3px solid var(--accent);padding:8px 12px;background:var(--panel);color:var(--ink2);font-size:13px}
footer{margin-top:48px;color:var(--muted);font-size:12px}
"""


def page(title: str, body: str, depth: int = 0) -> str:
    up = "../" * depth
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><link rel='icon' href='data:,'><style>{CSS}</style></head><body><main>{body}"
            f"<footer>ECDAT · SIH 2026 · PS 26164 · <a href='{up}index.html'>evidence hub</a></footer></main></body></html>")


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
<p class='sub'>{o['repos']} public codebases scanned with ECDAT on 18 Sep 2026. Every row links to a CycloneDX 1.7 Cryptographic
Bill of Materials signed with ML-DSA-65 (FIPS 204), a human-readable report and a VEX file.</p>
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
<p class='note'>"Observed" means found in the project's own code, configuration, certificates or binaries. Algorithms a dependency merely
<i>can</i> provide are listed in the CBOM as dependency inventory ({o['library_capability_only']:,} of them) but never counted as use.
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
<p class='sub'>Which public sites already negotiate hybrid post-quantum key exchange (X25519MLKEM768)? {india['reachable']} Indian public sites
across NCIIPC's seven critical sectors, and 25 global reference sites. Taken {html.escape(s['taken_utc'].replace('T', ' ').replace('+00:00', ''))} UTC with ECDAT's protocol scanner.</p>
<p class='small'><span style='color:var(--india)'>■</span> Indian sector &nbsp; <span style='color:var(--ref)'>■</span> global reference</p>
{svg}
<div class='tiles'><div class='tile'><div class='v'>{india['pq_hybrid_kex_pct']}%</div><div class='l'>of Indian sites use post-quantum key exchange (global reference: {sectors['Global reference']['pq_hybrid_kex_pct']}%)</div></div>
<div class='tile'><div class='v'>{india['rsa_cert_pct']:.0f}%</div><div class='l'>of Indian sites present an RSA certificate</div></div>
<div class='tile'><div class='v'>0%</div><div class='l'>post-quantum certificates anywhere: no public CA issues them yet</div></div>
<div class='tile'><div class='v'>22 / 25</div><div class='l'>Indian sites that pass sit behind a CDN that enabled it for them</div></div></div>
<details><summary>Table view</summary><table><thead><tr><th>sector</th><th class='num'>reachable / probed</th><th class='num'>hybrid PQ key exchange</th>
<th class='num'>TLS 1.3</th><th class='num'>RSA leaf cert</th><th class='num'>ECDSA leaf cert</th></tr></thead><tbody>{table}</tbody></table></details>
<h2>Method</h2>
<p class='note'>Per site, two connections, exactly what a browser does on a visit: one TLS 1.3 ClientHello offering X25519MLKEM768 first (which
key-exchange group does the server pick?) and one normal handshake (version, cipher suite, leaf certificate). No crawling, no vulnerability
probing, no authentication. Only sector totals are published; the list of sites is not. A site's result reflects its public edge (often a CDN),
not necessarily its internal systems. Snapshot, not a ranking.</p>"""
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
    video = f"<a class='door' href='{html.escape(video_url)}'><b>Watch the 3-minute demo →</b><span>Scan, reconcile, score, plan, export, verify.</span></a>" if video_url else ""
    body = f"""
<h1>ECDAT</h1>
<p class='sub'>Find every piece of cryptography. See which of it a quantum computer will break. Plan the fix.</p>
<p><span class='tag'>SIH 2026</span><span class='tag'>PS 26164 · NTRO</span><span class='tag'>Blockchain &amp; Cybersecurity</span><span class='tag'>{html.escape(team)}</span></p>
<div class='doors'>
<a class='door' href='atlas/index.html'><b>CBOM Atlas →</b><span>{o['repos']} public codebases scanned, including India's open digital public infrastructure. Every inventory is a CycloneDX 1.7 CBOM signed with ML-DSA-65.</span></a>
<a class='door' href='snapshot/index.html'><b>India quantum-readiness snapshot →</b><span>{india['reachable']} public sites across NCIIPC's seven sectors: {india['pq_hybrid_kex_pct']}% use post-quantum key exchange, versus {glob['pq_hybrid_kex_pct']}% of global reference sites.</span></a>
<a class='door' href='dashboard/index.html'><b>Try the dashboard →</b><span>The real ECDAT dashboard on real scans. Switch scans, drag the quantum-year presets, open any asset's evidence.</span></a>
{video}
</div>
<h2>Check our work</h2>
<pre>git clone {html.escape(repo_url)} &amp;&amp; cd ecdat &amp;&amp; pip install -e .
ecdat verify cbom.json --pubkey ecdat-mldsa65.pub</pre>
<p class='small'>Public key: <a href='ecdat-mldsa65.pub'>ecdat-mldsa65.pub</a> · SHA-256 fingerprint <span class='mono'>{pub_fpr}</span><br>
Source: <a href='{html.escape(repo_url)}'>{html.escape(repo_url)}</a> · {tests} automated tests · runs fully offline</p>
<p class='note'>The atlas scans each repository's default branch as downloaded on 18 Sep 2026. "Observed" means found in the project's own code,
configuration, certificates or binaries; algorithms a dependency merely can provide are listed separately and never counted as use. The readiness
snapshot makes two browser-equivalent connections per site and publishes only sector totals.</p>"""
    (SITE / "index.html").write_text(page("ECDAT · evidence", body, 0), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    remote = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    ap.add_argument("--repo-url", default=remote.removesuffix(".git") or "https://github.com/<owner>/ecdat")
    ap.add_argument("--video-url", default="")
    ap.add_argument("--team", default="Team <name>")
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
