import json
from pathlib import Path

from ecdat.collectors.base import Target
from ecdat.collectors.source import SourceCollector
from ecdat.collectors.dependency import DependencyCollector
from ecdat.knowledge import KnowledgeBase
from ecdat.model import CryptoAsset, Evidence, RawFinding, ScanResult
from ecdat.normalize import certin, cyclonedx, merge, signing

ZOO = Path(__file__).parent / "fixtures" / "zoo" / "src"
kb = KnowledgeBase()


def _finding(collector, name, comp="app", line=1, conf="high", **props):
    return RawFinding(collector, "algorithm", name, "a.py", line, f"{name} here", conf, comp, props, {"is_test": False})


def test_merge_dedupes_and_corroborates():
    fs = [_finding("source", "RSA", key_size=2048, primitive="pke"), _finding("opengrep", "RSA", conf="medium", key_size=2048),
          _finding("source", "MD5", comp="app", line=9, primitive="hash")]
    assets, comps = merge.merge(fs, [Target("dir", "x", "app", "internal")], kb)
    rsa = [a for a in assets if a.name == "RSA"][0]
    assert len(rsa.evidence) == 2 and rsa.context["corroborated"] is True and rsa.confidence == "high"
    assert rsa.key_size == 2048 and rsa.primitive == "pke" and rsa.oid == "1.2.840.113549.1.1.1"
    assert rsa.classical_security_level == 112 and rsa.family == "RSASSA-PKCS1"
    assert len(assets) == 2 and comps[0].name == "app"


def test_merge_libraries_become_components_with_provides():
    py = Target("dir", str(ZOO / "python"), "payments-api", "external", props={"use_syft": False})
    fs = SourceCollector().collect(py, kb) + DependencyCollector().collect(py, kb)
    assets, comps = merge.merge(fs, [py], kb)
    libs = [c for c in comps if c.type == "library"]
    assert any(c.name == "cryptography" for c in libs)
    rsa = [a for a in assets if a.name == "RSA" and not a.context.get("from_library_only")][0]
    assert rsa.provided_by is not None
    lib_only = [a for a in assets if a.context.get("from_library_only")]
    assert lib_only and all(a.confidence == "low" for a in lib_only)


def _small_result():
    py = Target("dir", str(ZOO / "python"), "payments-api", "external", props={"use_syft": False})
    ng = Target("dir", str(ZOO / "nginx"), "edge-lb", "external")
    fs = SourceCollector().collect(py, kb) + DependencyCollector().collect(py, kb) + SourceCollector().collect(ng, kb)
    assets, comps = merge.merge(fs, [py, ng], kb)
    certin.apply(assets)
    return ScanResult(name="zoo-mini", targets=[py.to_dict(), ng.to_dict()], components=comps, assets=assets, id="test123")


def test_cyclonedx_17_valid():
    res = _small_result()
    bom = cyclonedx.to_bom(res)
    assert bom["specVersion"] == "1.7" and bom["bomFormat"] == "CycloneDX"
    errs = cyclonedx.validate(bom)
    assert errs == [], errs[:5]
    crypto = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    assert crypto and all("assetType" in c["cryptoProperties"] for c in crypto)
    rsa = [c for c in crypto if c["name"].startswith("RSA-2048")][0]
    assert rsa["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"
    assert rsa["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.1"
    assert any(o.get("line") for o in rsa["evidence"]["occurrences"])
    proto = [c for c in crypto if c["cryptoProperties"]["assetType"] == "protocol"]
    assert proto and proto[0]["cryptoProperties"]["protocolProperties"]["type"] == "tls"
    provides = [d for d in bom["dependencies"] if d.get("provides")]
    assert provides, "library -> algorithm provides edges expected"


def test_signing_roundtrip(tmp_path):
    res = _small_result()
    p = cyclonedx.write(cyclonedx.to_bom(res), tmp_path / "cbom.json")
    sig = signing.sign_file(p, tmp_path / "keys")
    assert sig.exists() and signing.verify_file(p)
    p.write_text(p.read_text().replace("RSA", "RSB", 1))
    assert signing.verify_file(p) is False


def test_certin_completeness():
    cert = CryptoAsset(bom_ref="c1", asset_type="certificate", name="pay.zoo.local", props={
        "subject": "CN=pay", "issuer": "CN=ca", "not_before": "2026-01-01", "not_after": "2027-01-01", "signature_algorithm_oid": "1.2",
        "public_key_algorithm": "RSA", "format": "X.509", "extension": ".crt"})
    assert certin.completeness(cert)["pct"] == 100.0
    alg = CryptoAsset(bom_ref="a1", asset_type="algorithm", name="RSA", primitive="pke", crypto_functions=["keygen"], classical_security_level=112)
    c = certin.completeness(alg)
    assert c["pct"] < 100 and "OID" in c["missing"]
    s = certin.summary([cert, alg])
    assert s["by_type"]["certificate"] == 100.0 and s["overall_pct"] < 100
