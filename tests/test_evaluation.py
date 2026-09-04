from pathlib import Path

import pytest

from ecdat import config as cfgmod, evaluation, pipeline

ZOO = Path(__file__).parent / "fixtures" / "zoo"


@pytest.fixture(scope="module")
def zoo_result():
    from scripts.build_zoo import build_all
    if not (ZOO / "images" / "zoo-oci.tar").exists():
        build_all(ZOO)
    return pipeline.run(cfgmod.load(ZOO / "ecdat.yaml"))


def test_zoo_meets_precision_recall_gates(zoo_result):
    rep = evaluation.evaluate(zoo_result, ZOO / "truth.yaml")
    assert rep["fn"] == 0, f"missed planted assets: {rep['missed']}"
    assert not rep["negative_hits"], rep["negative_hits"]
    assert rep["precision"] >= 0.85 and rep["recall"] >= 0.95, rep
    assert rep["gates"]["passed"]
    assert set(rep["per_collector"]) >= {"source", "certificate", "binary", "pcap"}


def test_evaluation_reports_misses(zoo_result, tmp_path):
    t = tmp_path / "truth.yaml"
    t.write_text("expected:\n  - {component: payments-api, name: RSA, key_size: 2048}\n  - {component: payments-api, name: RC4}\n", encoding="utf-8")
    rep = evaluation.evaluate(zoo_result, t)
    assert rep["fn"] == 1 and "payments-api:RC4" in rep["missed"] and rep["recall"] == 0.5
