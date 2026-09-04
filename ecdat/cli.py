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
    console.print(f"[bold]ECDAT {__version__}[/] scanning [cyan]{cfg.name}[/] ({len(cfg.targets)} targets)")
    with console.status("collecting...", spinner="line") as status:
        def progress(stage, msg):
            status.update(f"[{stage}] {msg}")
            console.log(f"[{stage}] {msg}")
        result = pipeline.run(cfg, progress)
    files = pipeline.write_outputs(result, out, sign=not no_sign)
    _print_summary(result)
    console.print("\n[bold]outputs[/]")
    for k, v in files.items():
        console.print(f"  {k:10s} {v}")
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
