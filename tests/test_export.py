import csv
import io
import json

import pytest

from ecdat.enrich import agility, exposure, lifetime
from ecdat.export import csv_export, html_report, pdf_report, sarif
from ecdat.knowledge import KnowledgeBase
from ecdat.model import Component, CryptoAsset, Evidence, ScanParams, ScanResult
from ecdat.plan import optimizer, patches, pqc, vex
from ecdat.risk import frameworks, mosca, quantum

kb = KnowledgeBase()


@pytest.fixture(scope="module")
def result():
    comps = [Component("c-pay", "payments-api", zone="external", data_class="financial", criticality="high"),
             Component("c-edge", "edge-lb", zone="external"),
             Component("c-hsm", "legacy-hsm-agent", zone="internal", data_class="defence", criticality="critical")]

    def mk(name, primitive, comp, loc, line, snippet, asset_type="algorithm", props=None, usage="security", collector="source"):
        return CryptoAsset(bom_ref=f"ref-{name}-{loc}-{line}", asset_type=asset_type, name=name, primitive=primitive, component=comp,
                           evidence=[Evidence(collector, loc, line, snippet, "high", {})],
                           props={"api": snippet.split("(")[0], "language": "python", "literal": True, **(props or {})},
                           context={"usage": usage}, certin={"present": ["name", "primitive"], "missing": ["oid"], "pct": 66.7})

    assets = [
        mk("RSA", "pke", "payments-api", "payments/auth.py", 12, "rsa.generate_private_key(public_exponent=65537, key_size=2048)", props={"key_size": 2048, "function": "keygen"}),
        mk("ECDSA", "signature", "payments-api", "payments/auth.py", 20, "ec.ECDSA(hashes.SHA256())"),
        mk("MD5", "hash", "payments-api", "utils/cache.py", 6, "hashlib.md5(url.encode()).hexdigest()  # etag", usage="non-security"),
        mk("ECDH", "key-agree", "edge-lb", "nginx.conf", 9, "ssl_ecdh_curve prime256v1;", props={"api": "config", "curve": "prime256v1", "language": None}),
        mk("RSA", "pke", "legacy-hsm-agent", "legacy.c", 9, "RSA_generate_key_ex(rsa, 2048, e, NULL)", props={"key_size": 2048, "language": "c", "function": "keygen"}),
        mk("=AES-256", "block-cipher", "payments-api", "payments/auth.py", 25, "AESGCM(key)"),
    ]
    assets[-1].name = "AES-256"
    assets[-1].component = "=payments-api"   # formula-injection probe
    params = ScanParams(z_year=2035, now_year=2026, profile="cii", engineers=2, months=3)
    exposure.apply(assets, comps)
    lifetime.apply(assets, comps, kb)
    agility.apply(assets, {"payments-api": {"python": "3.11"}, "legacy-hsm-agent": {"c": "?"}}, kb)
    quantum.apply(assets, kb)
    mosca.apply(assets, params, kb)
    frameworks.apply(assets, params, kb)
    pqc.apply(assets, kb, params)
    patches.apply(assets)
    res = ScanResult(name="zoo-mini", assets=assets, components=comps, params=params)
    res.plan = optimizer.plan(assets, params.engineers, params.months)
    res.stats = mosca.summarize(assets)
    v = vex.build(res)
    res.stats["vex"] = len(v["vulnerabilities"])
    return res


def test_sarif_shape(result):
    s = sarif.to_sarif(result)
    assert s["version"] == "2.1.0" and s["runs"][0]["tool"]["driver"]["name"] == "ECDAT"
    res = s["runs"][0]["results"]
    assert len(res) == len(result.assets)
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in res)
    assert {r["level"] for r in res} <= {"error", "warning", "note"}
    json.dumps(s)


def test_csv_hardened(result):
    text = csv_export.render(result)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == len(result.assets) and rows[0]["tier"]
    probe = [r for r in rows if r["name"] == "AES-256"][0]
    assert probe["component"].startswith("'=")
    assert text.count("\r\n") >= len(rows)


def test_html_report(result, tmp_path):
    html = html_report.render(result)
    assert "ALREADY EXPOSED" in html and "ACT NOW" in html and "2035" in html
    assert "<svg" in html and "Methodology" in html and "CERT-In" in html
    assert "payments/auth.py" in html and "Migration plan" in html
    assert "<script" not in html
    p = html_report.write(result, tmp_path / "r.html")
    assert p.stat().st_size > 5000


def test_pdf_report(result, tmp_path):
    p = pdf_report.write(result, tmp_path / "r.pdf")
    data = p.read_bytes()
    assert p.exists() and len(data) > 3_000
    assert data[:5] == b"%PDF-" and data.count(b"/Type /Page") >= 2   # summary page + appendix page


def test_pipeline_layers_agree(result):
    tiers = {a.name: a.risk.tier for a in result.assets if a.component == "legacy-hsm-agent"}
    assert tiers["RSA"] == "EXPOSED"                     # defence data (30 y) + rigid C code vs Z = 9 y
    md5 = [a for a in result.assets if a.name == "MD5"][0]
    assert md5.risk.tier == "SAFE" and md5.recommendation.target is None
    assert result.plan["items"] and result.plan["capacity_weeks"] == 26.0


def test_verify_command_trusted_key_tamper_and_wrong_key(tmp_path):
    from typer.testing import CliRunner

    from ecdat.cli import app
    from ecdat.normalize import signing
    bom = tmp_path / "cbom.json"
    bom.write_text('{"bomFormat": "CycloneDX", "components": [{"name": "RSA"}]}', encoding="utf-8")
    signing.sign_file(bom, tmp_path / "keys")
    pub = tmp_path / "keys" / "ecdat-mldsa65.pub"
    run = CliRunner().invoke
    assert run(app, ["verify", str(bom), "--pubkey", str(pub)]).exit_code == 0
    other = tmp_path / "other"
    signing.load_or_create_keys(other)
    assert run(app, ["verify", str(bom), "--pubkey", str(other / "ecdat-mldsa65.pub")]).exit_code == 1
    bom.write_text(bom.read_text(encoding="utf-8").replace("RSA", "AES"), encoding="utf-8")
    assert run(app, ["verify", str(bom), "--pubkey", str(pub)]).exit_code == 1
