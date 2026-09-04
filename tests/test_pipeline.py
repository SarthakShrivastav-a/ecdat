import json
from pathlib import Path

import pytest

from ecdat import config as cfgmod, pipeline
from ecdat.model import ScanParams
from ecdat.normalize import cyclonedx

ZOO = Path(__file__).parent / "fixtures" / "zoo"


@pytest.fixture(scope="module")
def zoo_result(tmp_path_factory):
    from scripts.build_zoo import build_all
    if not (ZOO / "images" / "zoo-oci.tar").exists() or not (ZOO / "pcaps" / "smtp_starttls.pcap").exists():
        build_all(ZOO)
    cfg = cfgmod.load(ZOO / "ecdat.yaml")
    res = pipeline.run(cfg)
    out = tmp_path_factory.mktemp("out")
    files = pipeline.write_outputs(res, out / "zoo")
    return res, out / "zoo", files


def test_pipeline_produces_assets_and_tiers(zoo_result):
    res, out, files = zoo_result
    assert len(res.assets) >= 25
    tiers = res.stats["tiers"]
    assert tiers.get("EXPOSED", 0) >= 1, tiers          # legacy-hsm-agent: defence data (30 y) + RSA in code
    assert tiers.get("SAFE", 0) >= 1
    assert all(a.risk and a.agility and a.certin for a in res.assets)
    names = {a.name for a in res.assets}
    assert {"RSA", "MD5", "AES-256", "3DES", "ECDSA"} <= names
    # context: the etag MD5 is non-security, the test SHA-1 is test-only
    md5 = [a for a in res.assets if a.name == "MD5" and a.component == "payments-api"][0]
    assert md5.context["usage"] == "non-security" and md5.risk.tier == "SAFE"
    # collectors all ran
    per = res.stats["collectors"]["per_collector"]
    assert {"source", "dependency", "certificate", "binary", "container", "pcap"} <= set(per)
    assert not res.stats["collectors"]["errors"], res.stats["collectors"]["errors"]


def test_outputs_written_and_cbom_valid(zoo_result):
    res, out, files = zoo_result
    for k in ("result", "cbom", "vex", "sarif", "csv", "html", "summary"):
        assert Path(files[k]).exists() and Path(files[k]).stat().st_size > 100, k
    assert res.stats["cbom_valid"] is True, res.stats.get("cbom_errors")
    bom = json.loads((out / "cbom.json").read_text(encoding="utf-8"))
    assert bom["specVersion"] == "1.7" and bom.get("vulnerabilities")
    assert (out / "cbom.json.mldsa65.sig").exists()
    from ecdat.normalize import signing
    assert signing.verify_file(out / "cbom.json")


def test_plan_is_greedy_and_bounded(zoo_result):
    res, out, files = zoo_result
    p = res.plan
    assert p["items"] and p["used_weeks"] <= p["capacity_weeks"] + 1e-6
    ratios = [it["priority"] / max(it["effort_weeks"], 0.1) for it in p["items"] if "priority" in it and "effort_weeks" in it]
    assert ratios == sorted(ratios, reverse=True) or len(ratios) < 2


def test_recompute_z_slider(zoo_result):
    res, out, files = zoo_result
    loaded = pipeline.load_result(out / "result.json")
    assert len(loaded.assets) == len(res.assets)
    before = loaded.stats["tiers"].get("EXPOSED", 0)
    p = ScanParams(**{**loaded.params.to_dict(), "z_year": 2032})
    pipeline.recompute(loaded, p)
    after = loaded.stats["tiers"].get("EXPOSED", 0)
    assert after >= before and loaded.params.z_year == 2032
    p2 = ScanParams(**{**loaded.params.to_dict(), "z_year": 2060})
    pipeline.recompute(loaded, p2)
    assert loaded.stats["tiers"].get("EXPOSED", 0) <= after


def test_cli_scan(tmp_path):
    from typer.testing import CliRunner
    from ecdat.cli import app
    r = CliRunner().invoke(app, ["scan", "-c", str(ZOO / "ecdat.yaml"), "-o", str(tmp_path / "o"), "--no-sign"])
    assert r.exit_code == 0, r.output[-2000:]
    assert (tmp_path / "o" / "cbom.json").exists() and (tmp_path / "o" / "report.html").exists()
