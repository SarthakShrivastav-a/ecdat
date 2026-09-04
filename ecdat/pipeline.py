"""The seven-layer pipeline: targets -> collectors -> CBOM (merge) -> enrichment -> risk -> plan -> outputs."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from ecdat import tools
from ecdat.collectors import run_collectors
from ecdat.config import ScanConfig
from ecdat.enrich import agility, context, exposure, lifetime
from ecdat.export import csv_export, html_report, pdf_report, sarif
from ecdat.knowledge import KnowledgeBase
from ecdat.model import AgilityScore, Component, CryptoAsset, Evidence, Recommendation, RiskAssessment, ScanParams, ScanResult
from ecdat.normalize import certin, cyclonedx, merge, signing
from ecdat.plan import optimizer, patches, pqc, vex
from ecdat.risk import frameworks, mosca, quantum

Progress = Callable[[str, str], None]


def _runtimes_by_component(findings) -> dict:
    out: dict = {"*": {}}
    for f in findings:
        if f.asset_type == "library" and f.name.startswith("runtime:"):
            rt = f.props.get("runtime") or {}
            out.setdefault(f.component, {}).update(rt)
    return out


def analyse(assets: list[CryptoAsset], components: list[Component], params: ScanParams, kb: KnowledgeBase,
            runtimes: dict | None = None) -> None:
    """Layers 4-6 on already-merged assets (also used by recompute)."""
    context.apply(assets)
    exposure.apply(assets, components)
    lifetime.apply(assets, components, kb)
    agility.apply(assets, runtimes or {"*": {}}, kb)
    quantum.apply(assets, kb)
    mosca.apply(assets, params, kb)
    frameworks.apply(assets, params, kb)
    pqc.apply(assets, kb, params)
    patches.apply(assets)
    certin.apply(assets)


def finish(result: ScanResult) -> ScanResult:
    """Plan + summaries + VEX (re-run after any recompute)."""
    result.plan = optimizer.plan(result.assets, result.params.engineers, result.params.months)
    result.stats.update(mosca.summarize(result.assets))
    result.stats["certin"] = certin.summary(result.assets)
    result.stats["asset_types"] = {}
    for a in result.assets:
        result.stats["asset_types"][a.asset_type] = result.stats["asset_types"].get(a.asset_type, 0) + 1
    result.stats["components"] = len([c for c in result.components if (c.type if isinstance(c, Component) else c.get("type")) != "library"])
    result.stats["libraries"] = len([c for c in result.components if (c.type if isinstance(c, Component) else c.get("type")) == "library"])
    vdoc = vex.build(result)
    result.plan["vex"] = vdoc.get("vulnerabilities", [])
    result.plan["vex_document"] = vdoc
    return result


def run(config: ScanConfig, progress: Progress | None = None) -> ScanResult:
    kb = KnowledgeBase()
    t0 = datetime.now(timezone.utc)

    def prog(target: str, coll: str, n: int) -> None:
        if progress:
            progress("collect", f"{target}: {coll} -> {n} findings")

    findings, cstats = run_collectors(config.targets, kb, config.collectors, prog)
    if progress:
        progress("merge", f"{len(findings)} raw findings")
    assets, components = merge.merge(findings, config.targets, kb)
    runtimes = _runtimes_by_component(findings)
    if progress:
        progress("analyse", f"{len(assets)} assets, {len(components)} components")
    analyse(assets, components, config.params, kb, runtimes)
    result = ScanResult(name=config.name, targets=[t.to_dict() for t in config.targets], components=components, assets=assets,
                        params=config.params, stats={"collectors": cstats, "runtimes": runtimes}, tool_versions=tools.versions(),
                        id=uuid.uuid4().hex[:12])
    finish(result)
    result.stats["duration_s"] = round((datetime.now(timezone.utc) - t0).total_seconds(), 2)
    if progress:
        progress("done", f"{result.stats.get('tiers')}")
    return result


def recompute(result: ScanResult, params: ScanParams) -> ScanResult:
    kb = KnowledgeBase()
    result.params = params
    mosca.recompute(result, params, kb)
    frameworks.apply(result.assets, params, kb)
    pqc.apply(result.assets, kb, params)
    patches.apply(result.assets)
    certin.apply(result.assets)
    return finish(result)


# ------------------------------------------------------------------------------------------------
# outputs
# ------------------------------------------------------------------------------------------------
def summary_md(result: ScanResult) -> str:
    s = result.stats
    tiers = s.get("tiers", {})
    lines = [f"# ECDAT scan: {result.name}", "", f"- id: `{result.id}`  time: {result.timestamp}  duration: {s.get('duration_s')} s",
             f"- targets: {len(result.targets)}  components: {s.get('components')}  libraries: {s.get('libraries')}  assets: {len(result.assets)}",
             f"- Z (CRQC year): {result.params.z_year}  profile: {result.params.profile}  budget: {result.params.engineers} engineers x {result.params.months} months",
             "", "## Tiers", ""]
    for t in ("EXPOSED", "ACT_NOW", "MONITOR", "SAFE"):
        lines.append(f"- {t}: {tiers.get(t, 0)}")
    c = s.get("certin", {})
    lines += ["", f"## CERT-In Table 9 completeness: {c.get('overall_pct')}%", ""]
    for k, v in (c.get("by_type") or {}).items():
        lines.append(f"- {k}: {v}%")
    p = result.plan or {}
    lines += ["", f"## Migration plan ({p.get('engineers')} engineers x {p.get('months')} months = {p.get('capacity_weeks')} eng-weeks)", "",
              f"- covers {p.get('covered_pct')}% of risk with {p.get('used_weeks')} eng-weeks; {len(p.get('uncovered', []))} items left over", ""]
    for i, it in enumerate((p.get("items") or [])[:15], 1):
        lines.append(f"{i}. {it.get('name')} [{it.get('component')}] tier={it.get('tier')} -> {it.get('target')}  {it.get('effort_weeks')} wk")
    cs = s.get("collectors", {})
    lines += ["", "## Collectors", ""] + [f"- {k}: {v}" for k, v in (cs.get("per_collector") or {}).items()]
    if cs.get("errors"):
        lines += ["", "## Collector errors", ""] + [f"- {e}" for e in cs["errors"]]
    lines += ["", "## Honesty notes", "",
              "- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).",
              "- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.",
              "- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.",
              "- Patches are suggestions with evidence; nothing is applied automatically."]
    return "\n".join(lines) + "\n"


def write_outputs(result: ScanResult, out_dir: str | Path, sign: bool = True) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    files = {}
    (out / "result.json").write_text(json.dumps(result.to_dict(), indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    files["result"] = out / "result.json"
    bom = cyclonedx.to_bom(result)
    errs = cyclonedx.validate(bom)
    result.stats["cbom_valid"] = not errs
    result.stats["cbom_errors"] = errs[:20]
    files["cbom"] = cyclonedx.write(bom, out / "cbom.json")
    if sign:
        try:
            files["signature"] = signing.sign_file(out / "cbom.json", out.parent / "keys" if out.parent.name else out / "keys")
        except Exception as exc:  # signing must never block a scan
            result.stats["signature_error"] = str(exc)[:200]
    (out / "vex.json").write_text(json.dumps(result.plan.get("vex_document", {}), indent=2, default=str), encoding="utf-8")
    files["vex"] = out / "vex.json"
    (out / "findings.sarif").write_text(json.dumps(sarif.to_sarif(result), indent=2, default=str), encoding="utf-8")
    files["sarif"] = out / "findings.sarif"
    files["csv"] = csv_export.write(result, out / "assets.csv")
    files["html"] = html_report.write(result, out / "report.html")
    try:
        files["pdf"] = pdf_report.write(result, out / "report.pdf")
    except Exception as exc:
        result.stats["pdf_error"] = str(exc)[:200]
    (out / "summary.md").write_text(summary_md(result), encoding="utf-8")
    files["summary"] = out / "summary.md"
    # re-write result.json so it carries cbom_valid etc.
    (out / "result.json").write_text(json.dumps(result.to_dict(), indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    return files


# ------------------------------------------------------------------------------------------------
# loading a result back (API / recompute / gate)
# ------------------------------------------------------------------------------------------------
def _asset_from_dict(d: dict) -> CryptoAsset:
    a = CryptoAsset(**{k: v for k, v in d.items() if k in CryptoAsset.__dataclass_fields__ and k not in ("evidence", "agility", "risk", "recommendation")})
    a.evidence = [Evidence(**{k: v for k, v in e.items() if k in Evidence.__dataclass_fields__}) for e in d.get("evidence") or []]
    if d.get("agility"):
        a.agility = AgilityScore(**{k: v for k, v in d["agility"].items() if k in AgilityScore.__dataclass_fields__})
    if d.get("risk"):
        a.risk = RiskAssessment(**{k: v for k, v in d["risk"].items() if k in RiskAssessment.__dataclass_fields__})
    if d.get("recommendation"):
        a.recommendation = Recommendation(**{k: v for k, v in d["recommendation"].items() if k in Recommendation.__dataclass_fields__})
    return a


def result_from_dict(d: dict) -> ScanResult:
    params = ScanParams(**{k: v for k, v in (d.get("params") or {}).items() if k in ScanParams.__dataclass_fields__})
    comps = [Component(**{k: v for k, v in c.items() if k in Component.__dataclass_fields__}) for c in d.get("components") or []]
    assets = [_asset_from_dict(a) for a in d.get("assets") or []]
    return ScanResult(name=d.get("name", "scan"), targets=d.get("targets") or [], components=comps, assets=assets, params=params,
                      stats=d.get("stats") or {}, plan=d.get("plan") or {}, tool_versions=d.get("tool_versions") or {},
                      timestamp=d.get("timestamp") or "", id=d.get("id") or "")


def load_result(path: str | Path) -> ScanResult:
    return result_from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
