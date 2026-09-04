import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ecdat import config as cfgmod, pipeline
from ecdat.api.server import create_app

ZOO = Path(__file__).parent / "fixtures" / "zoo"


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    out = tmp_path_factory.mktemp("results")
    cfg = cfgmod.load(ZOO / "ecdat.yaml")
    cfg.targets = [t for t in cfg.targets if t.kind in ("dir", "certs") and t.name in ("payments-api", "edge-lb", "legacy-hsm-agent", "pki")]
    res = pipeline.run(cfg)
    pipeline.write_outputs(res, out / "zoo", sign=False)
    return TestClient(create_app(out)), res.id


def test_health_and_list(client):
    c, rid = client
    assert c.get("/api/health").json()["ok"] is True
    lst = c.get("/api/results").json()
    assert lst and lst[0]["id"] == rid and lst[0]["assets"] > 0


def test_result_and_recompute(client):
    c, rid = client
    r = c.get(f"/api/results/{rid}").json()
    assert r["params"]["z_year"] == 2041 and r["assets"]
    before = r["stats"]["tiers"].get("EXPOSED", 0)
    r2 = c.post(f"/api/results/{rid}/recompute", json={"z_year": 2032, "engineers": 2, "months": 3}).json()
    assert r2["params"]["z_year"] == 2032 and r2["stats"]["tiers"].get("EXPOSED", 0) >= before
    assert r2["plan"]["engineers"] == 2 and r2["plan"]["capacity_weeks"] < r["plan"]["capacity_weeks"]
    # original on disk untouched
    assert c.get(f"/api/results/{rid}").json()["params"]["z_year"] == 2041


def test_exports(client):
    c, rid = client
    assert c.get(f"/api/results/{rid}/cbom").json()["specVersion"] == "1.7"
    assert "vulnerabilities" in c.get(f"/api/results/{rid}/vex").json()
    assert c.get(f"/api/results/{rid}/sarif").json()["version"] == "2.1.0"
    assert c.get(f"/api/results/{rid}/csv").text.splitlines()[0]
    assert "EXPOSED" in c.get(f"/api/results/{rid}/report.html").text
    assert c.get(f"/api/results/{rid}/summary.md").text.startswith("# ECDAT scan")
    assert c.get("/api/results/nope").status_code == 404
