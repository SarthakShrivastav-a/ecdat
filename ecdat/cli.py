"""ECDAT command line."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from ecdat import __version__, tools

app = typer.Typer(add_completion=False, help="ECDAT - Enterprise Cryptographic Discovery & Analysis Tool (CBOM + quantum risk)")
for _stream in (sys.stdout, sys.stderr):      # Windows consoles default to cp1252; keep unicode output safe
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
console = Console(highlight=False)


def _params_override(params, z_year, engineers, months, profile, no_external):
    if z_year:
        params.z_year = z_year
    if engineers:
        params.engineers = engineers
    if months:
        params.months = months
    if profile:
        params.profile = profile
    if no_external:
        params.use_external_tools = False
    return params


@app.command()
def scan(config: Path = typer.Option(..., "-c", "--config", exists=True, help="ecdat.yaml"),
         out: Path = typer.Option(Path("out"), "-o", "--out"), z_year: int = typer.Option(None, "--z-year"),
         engineers: int = typer.Option(None), months: int = typer.Option(None), profile: str = typer.Option(None, help="cii | enterprise"),
         no_external_tools: bool = typer.Option(False, "--no-external-tools"), no_sign: bool = typer.Option(False, "--no-sign")):
    """Run every applicable collector, build the CBOM, score risk, plan migration, write all outputs."""
    from ecdat import config as cfgmod, pipeline
    cfg = cfgmod.load(config)
    _params_override(cfg.params, z_year, engineers, months, profile, no_external_tools)
    if no_external_tools:
        import os
        os.environ["ECDAT_NO_EXTERNAL_TOOLS"] = "1"
    from ecdat.tui import ScanReporter

    svg = ScanReporter.wants_svg()
    if svg:                                   # record the whole session for the README / the demo video
        console.record = True
    rep = ScanReporter(console, cfg, __version__)
    rep.header()
    seen: set[str] = set()

    def progress(stage, msg, **data):
        if stage in ("collect-start", "collect") and "collect" not in seen:
            seen.add("collect")
            rep.phase(1, "DISCOVER", "every collector that applies to every target")
            rep.start_collect()
        elif stage == "merge" and "merge" not in seen:
            seen.add("merge")
            rep.stop_collect()
            rep.phase(2, "RECONCILE", "duplicates collapse into one asset with many proofs")
            console.print(f"  {msg}")
        elif stage == "analyse" and "analyse" not in seen:
            seen.add("analyse")
            rep.phase(3, "ANALYSE", "quantum class, HNDL scope, Mosca X + Y > Z, crypto-agility")
            console.print(f"  {msg}")
        rep.on_progress(stage, msg, **data)

    result = pipeline.run(cfg, progress)
    rep.stop_collect()
    rep.phase(4, "DECIDE", "tiers at this Z, then a plan that fits the budget")
    rep.tiers(result.stats)
    files = pipeline.write_outputs(result, out, sign=not no_sign)
    rep.summary(result, files)
    if svg:
        rep.save_svg(svg)
        console.print(f"[dim]session saved to[/] {svg}")
    if not result.stats.get("cbom_valid", True):
        console.print(f"[red]CBOM failed schema validation:[/] {result.stats.get('cbom_errors')[:3]}")
        raise typer.Exit(2)


def _print_summary(result):
    s = result.stats
    t = Table(title=f"{result.name}: {len(result.assets)} crypto assets across {s.get('components')} components", show_lines=False)
    t.add_column("tier"); t.add_column("count", justify="right")
    for k in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE"):
        t.add_row(k, str((s.get("tiers") or {}).get(k, 0)))
    console.print(t)
    c = s.get("certin") or {}
    console.print(f"CERT-In Table 9 completeness: [bold]{c.get('overall_pct')}%[/]   CBOM 1.7 valid: [bold]{s.get('cbom_valid')}[/]   "
                  f"Z={result.params.z_year}  plan covers {result.plan.get('covered_pct')}% of risk in {result.plan.get('used_weeks')} eng-weeks")


@app.command()
def recompute(result_json: Path = typer.Argument(..., exists=True), out: Path = typer.Option(None, "-o", "--out"),
              z_year: int = typer.Option(None, "--z-year"), engineers: int = typer.Option(None), months: int = typer.Option(None),
              profile: str = typer.Option(None)):
    """Re-score an existing result.json with a different Z year / budget / profile (the Z slider, on the CLI)."""
    from ecdat import pipeline
    res = pipeline.load_result(result_json)
    _params_override(res.params, z_year, engineers, months, profile, False)
    pipeline.recompute(res, res.params)
    _print_summary(res)
    if out:
        pipeline.write_outputs(res, out)
        console.print(f"written to {out}")


@app.command()
def report(result_json: Path = typer.Argument(..., exists=True), fmt: str = typer.Option("md", "--format", help="md | html | pdf | csv | sarif | cbom | vex"),
           out: Path = typer.Option(None, "-o", "--out")):
    """Render one output format from a saved result.json."""
    from ecdat import pipeline
    from ecdat.export import csv_export, html_report, pdf_report, sarif
    from ecdat.normalize import cyclonedx
    res = pipeline.load_result(result_json)
    if fmt == "md":
        text = pipeline.summary_md(res)
    elif fmt == "html":
        text = html_report.render(res)
    elif fmt == "csv":
        text = csv_export.render(res)
    elif fmt == "sarif":
        text = json.dumps(sarif.to_sarif(res), indent=2, default=str)
    elif fmt == "cbom":
        text = json.dumps(cyclonedx.to_bom(res), indent=2, default=str)
    elif fmt == "vex":
        text = json.dumps(res.plan.get("vex_document", {}), indent=2, default=str)
    elif fmt == "pdf":
        target = out or result_json.with_name("report.pdf")
        pdf_report.write(res, target)
        console.print(f"written {target}")
        return
    else:
        raise typer.BadParameter(fmt)
    if out:
        out.write_text(text, encoding="utf-8")
        console.print(f"written {out}")
    else:
        sys.stdout.write(text)


@app.command("tools")
def tools_cmd():
    """Show which optional engines are available and their versions."""
    t = Table(title="engines")
    t.add_column("tool"); t.add_column("version / status")
    for k, v in tools.versions().items():
        t.add_row(k, str(v) if v else "[red]not found[/] (pure-Python fallback in use)")
    console.print(t)


zoo_app = typer.Typer(help="crypto-zoo evaluation corpus")
app.add_typer(zoo_app, name="zoo")


@zoo_app.command("build")
def zoo_build(out: Path = typer.Option(None, "--out")):
    """Generate certificates, keystores, binaries, container image tars and pcaps for the evaluation corpus."""
    from scripts.build_zoo import ZOO, build_all
    truth = build_all(out or ZOO)
    console.print(json.dumps({k: sorted(v.keys()) for k, v in truth.items()}, indent=2))


@app.command("evaluate")
def evaluate(result_json: Path = typer.Argument(..., exists=True), truth: Path = typer.Option(None, "--truth"),
         out: Path = typer.Option(None, "-o", "--out"), strict: bool = typer.Option(False, help="exit 1 below the precision/recall gates")):
    """Precision / recall of a scan against the zoo ground truth."""
    from ecdat import evaluation as evalmod, pipeline
    res = pipeline.load_result(result_json)
    report_ = evalmod.evaluate(res, truth)
    evalmod.print_report(report_, console)
    if out:
        out.write_text(json.dumps(report_, indent=2, default=str), encoding="utf-8")
    if strict and not report_["gates"]["passed"]:
        raise typer.Exit(1)


@app.command()
def gate(config: Path = typer.Option(..., "-c", "--config", exists=True), baseline: Path = typer.Option(..., "--baseline", exists=True),
         policy: str = typer.Option("no-new-vulnerable", help="no-new-vulnerable | no-vulnerable | dst-m2"),
         out: Path = typer.Option(Path("out/gate"), "-o", "--out"), no_external_tools: bool = typer.Option(False, "--no-external-tools")):
    """CI gate: scan now, diff against a baseline CBOM, fail on newly introduced quantum-vulnerable crypto."""
    from ecdat import config as cfgmod, gate as gatemod, pipeline
    cfg = cfgmod.load(config)
    if no_external_tools:
        cfg.params.use_external_tools = False
    result = pipeline.run(cfg)
    current = pipeline.write_outputs(result, out, sign=False)
    base = json.loads(baseline.read_text(encoding="utf-8"))
    cur = json.loads(Path(current["cbom"]).read_text(encoding="utf-8"))
    g = gatemod.compare(base, cur, policy)
    (Path(out) / "gate.md").write_text(g.summary_md, encoding="utf-8")
    console.print(g.summary_md)
    raise typer.Exit(0 if g.passed else 1)


@app.command()
def verify(cbom: Path = typer.Argument(..., exists=True, help="cbom.json"),
           pubkey: Path = typer.Option(None, "--pubkey", exists=True, help="trusted ecdat-mldsa65.pub (base64)")):
    """Verify a CBOM's ML-DSA-65 (FIPS 204) signature. With --pubkey, also check it was signed by that key."""
    import base64

    from ecdat.normalize import signing
    sig_path = cbom.with_name(cbom.name + ".mldsa65.sig")
    if not sig_path.exists():
        console.print(f"[red]no signature file[/red] {sig_path.name}")
        raise typer.Exit(2)
    meta = json.loads(sig_path.read_text(encoding="utf-8"))
    if pubkey is not None:
        trusted = base64.b64decode(pubkey.read_text(encoding="utf-8").strip())
        if base64.b64decode(meta["public_key_b64"]) != trusted:
            console.print("[red]FAIL[/red] signed with a different key than the trusted one")
            raise typer.Exit(1)
    ok = signing.verify_file(cbom, sig_path)
    who = "trusted key" if pubkey is not None else "embedded key (integrity only; pass --pubkey to check the signer)"
    console.print(f"{'[green]OK[/green]' if ok else '[red]FAIL[/red]'}  {cbom.name}  {meta.get('algorithm')} ({meta.get('standard')}) "
                  f"sha256 {meta.get('sha256', '')[:16]}...  {who}")
    raise typer.Exit(0 if ok else 1)


@app.command()
def serve(results_dir: Path = typer.Argument(Path("out")), host: str = "127.0.0.1", port: int = 8787):
    """Serve the API + dashboard for a results directory (each sub-directory with result.json is one scan)."""
    import uvicorn
    from ecdat.api.server import create_app
    uvicorn.run(create_app(results_dir), host=host, port=port, log_level="info")


@app.callback()
def _main():
    pass


if __name__ == "__main__":
    app()
