"""FastAPI server: scan results, recompute (Z slider / budget), exports, background scans, and the dashboard."""
from __future__ import annotations

import copy
import json
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ecdat import __version__, tools
from ecdat.model import ScanParams

WEB_DIST = Path(__file__).resolve().parent.parent.parent / "web" / "dist"


class RecomputeBody(BaseModel):
    z_year: int | None = None
    engineers: int | None = None
    months: int | None = None
    profile: str | None = None


class ScanBody(BaseModel):
    config_yaml: str | None = None
    config: dict | None = None
    name: str | None = None


def create_app(results_dir: str | Path = "out") -> FastAPI:
    from ecdat import config as cfgmod, pipeline
    from ecdat.export import csv_export, html_report, sarif
    from ecdat.normalize import cyclonedx

    results_dir = Path(results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    app = FastAPI(title="ECDAT API", version=__version__)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    jobs: dict[str, dict] = {}
    cache: dict[str, object] = {}

    def _dirs() -> list[Path]:
        out = []
        if (results_dir / "result.json").exists():
            out.append(results_dir)
        out += sorted([p for p in results_dir.iterdir() if p.is_dir() and (p / "result.json").exists()], key=lambda p: p.stat().st_mtime, reverse=True)
        return out

    def _find(rid: str) -> Path:
        for d in _dirs():
            try:
                data = json.loads((d / "result.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            if data.get("id") == rid or d.name == rid:
                return d
        raise HTTPException(404, f"result {rid} not found")

    def _load(rid: str):
        d = _find(rid)
        key = f"{d}:{(d / 'result.json').stat().st_mtime}"
        if key not in cache:
            cache.clear()
            cache[key] = pipeline.load_result(d / "result.json")
        return copy.deepcopy(cache[key]), d

    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__, "results_dir": str(results_dir)}

    @app.get("/api/tools")
    def tools_():
        return tools.versions()

    @app.get("/api/results")
    def list_results():
        out = []
        for d in _dirs():
            try:
                data = json.loads((d / "result.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            s = data.get("stats", {})
            out.append({"id": data.get("id") or d.name, "dir": d.name, "name": data.get("name"), "timestamp": data.get("timestamp"),
                        "assets": len(data.get("assets", [])), "tiers": s.get("tiers"), "z_year": (data.get("params") or {}).get("z_year"),
                        "certin_pct": (s.get("certin") or {}).get("overall_pct"), "cbom_valid": s.get("cbom_valid")})
        return out

    @app.get("/api/results/{rid}")
    def get_result(rid: str):
        d = _find(rid)
        return JSONResponse(json.loads((d / "result.json").read_text(encoding="utf-8")))

    @app.post("/api/results/{rid}/recompute")
    def recompute(rid: str, body: RecomputeBody):
        res, _ = _load(rid)
        p = ScanParams(**res.params.to_dict())
        for k in ("z_year", "engineers", "months", "profile"):
            v = getattr(body, k)
            if v is not None:
                setattr(p, k, v)
        pipeline.recompute(res, p)
        return JSONResponse(json.loads(json.dumps(res.to_dict(), default=str)))

    @app.get("/api/results/{rid}/cbom")
    def cbom(rid: str):
        d = _find(rid)
        if (d / "cbom.json").exists():
            return FileResponse(d / "cbom.json", media_type="application/json", filename="cbom.json")
        res, _ = _load(rid)
        return JSONResponse(cyclonedx.to_bom(res))

    @app.get("/api/results/{rid}/cbom.sig")
    def cbom_sig(rid: str):
        d = _find(rid)
        p = d / "cbom.json.mldsa65.sig"
        if not p.exists():
            raise HTTPException(404, "unsigned")
        return FileResponse(p, media_type="application/json", filename="cbom.json.mldsa65.sig")

    @app.get("/api/results/{rid}/vex")
    def vex_(rid: str):
        res, d = _load(rid)
        if (d / "vex.json").exists():
            return FileResponse(d / "vex.json", media_type="application/json", filename="vex.json")
        return JSONResponse(res.plan.get("vex_document", {}))

    @app.get("/api/results/{rid}/sarif")
    def sarif_(rid: str):
        res, _ = _load(rid)
        return JSONResponse(sarif.to_sarif(res))

    @app.get("/api/results/{rid}/csv")
    def csv_(rid: str):
        res, _ = _load(rid)
        return PlainTextResponse(csv_export.render(res), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=assets.csv"})

    @app.get("/api/results/{rid}/report.html")
    def report_html(rid: str):
        res, _ = _load(rid)
        return HTMLResponse(html_report.render(res))

    @app.get("/api/results/{rid}/report.pdf")
    def report_pdf(rid: str):
        d = _find(rid)
        p = d / "report.pdf"
        if not p.exists():
            from ecdat.export import pdf_report
            res, _ = _load(rid)
            pdf_report.write(res, p)
        return FileResponse(p, media_type="application/pdf", filename="ecdat-report.pdf")

    @app.get("/api/results/{rid}/summary.md")
    def summary(rid: str):
        res, _ = _load(rid)
        return PlainTextResponse(pipeline.summary_md(res), media_type="text/markdown")

    @app.post("/api/scan")
    def scan(body: ScanBody):
        import yaml
        if body.config_yaml:
            data = yaml.safe_load(body.config_yaml) or {}
        elif body.config:
            data = body.config
        else:
            raise HTTPException(400, "config or config_yaml required")
        if body.name:
            data["name"] = body.name
        cfg = cfgmod.from_dict(data, results_dir)
        jid = uuid.uuid4().hex[:12]
        job = jobs[jid] = {"id": jid, "status": "running", "log": [], "result_id": None, "error": None}

        def work():
            try:
                res = pipeline.run(cfg, lambda st, msg: job["log"].append(f"[{st}] {msg}"))
                res.id = jid
                pipeline.write_outputs(res, results_dir / jid)
                job["status"] = "done"
                job["result_id"] = jid
            except Exception as exc:
                job["status"] = "error"
                job["error"] = str(exc)[:500]

        threading.Thread(target=work, daemon=True).start()
        return {"id": jid}

    @app.get("/api/scan/{jid}/status")
    def scan_status(jid: str):
        if jid not in jobs:
            raise HTTPException(404)
        return jobs[jid]

    if WEB_DIST.exists():
        app.mount("/", StaticFiles(directory=str(WEB_DIST), html=True), name="web")
    else:
        @app.get("/", response_class=HTMLResponse)
        def index():
            links = "".join(f'<li><a href="/api/results/{r["id"]}/report.html">{r["name"]} ({r["id"]})</a></li>' for r in list_results())
            return f"<h1>ECDAT {__version__}</h1><p>Dashboard not built (run <code>npm run build</code> in web/). Reports:</p><ul>{links}</ul>"
    return app
