from pathlib import Path

import pytest

from ecdat.collectors.base import Target
from ecdat.collectors.binary import BinaryCollector
from ecdat.knowledge import KnowledgeBase

kb = KnowledgeBase()


@pytest.fixture(scope="module")
def bins(tmp_path_factory):
    from scripts.build_zoo import build_binaries
    out = tmp_path_factory.mktemp("bin")
    truth = build_binaries(out)
    return out, truth


def test_synthetic_binary_constants_and_version(bins):
    out, truth = bins
    fs = BinaryCollector().collect(Target("dir", str(out), "zoobin", "internal"), kb)
    lib = [f for f in fs if f.location == "libzoocrypto.so"]
    names = {f.name for f in lib if f.asset_type == "algorithm"}
    assert "AES" in names and "SHA-256" in names
    assert all(f.confidence in ("medium", "low") and f.context["best_effort"] for f in lib)
    ossl = [f for f in lib if f.asset_type == "library" and f.name == "openssl"][0]
    assert ossl.props["version"] == "1.1.1w" and "RSA" in ossl.props["provides"]
    assert any(f.name == "RSA" and f.props["method"] == "go-import" for f in lib)


def test_go_binary_import_paths(bins):
    out, truth = bins
    if "zoobin" not in truth:
        pytest.skip("go toolchain unavailable")
    fs = BinaryCollector().collect(Target("binary", str(out / "zoobin"), "zoobin", "internal"), kb)
    names = {f.name for f in fs if f.asset_type == "algorithm"}
    assert {"RSA", "ECDSA", "SHA-256", "AES"} <= names
    assert any(f.asset_type == "protocol" and f.name == "TLS" for f in fs)
