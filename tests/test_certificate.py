from pathlib import Path

import pytest

from ecdat.collectors.base import Target
from ecdat.collectors.certificate import CertificateCollector, parse_x509
from ecdat.knowledge import KnowledgeBase

kb = KnowledgeBase()


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    from scripts.build_zoo import build_certs
    out = tmp_path_factory.mktemp("certs")
    truth = build_certs(out)
    return out, truth


def _collect(path, **props):
    t = Target("certs", str(path), "pki", "external", props={"use_theia": False, **props})
    return CertificateCollector().collect(t, kb)


def test_rsa_cert_fields(certs):
    out, truth = certs
    fs = _collect(out)
    c = [f for f in fs if f.asset_type == "certificate" and f.location == "rsa2048_sha256.crt"][0]
    assert c.props["public_key_algorithm"] == "RSA" and c.props["key_size"] == 2048
    assert c.props["signature_hash"] == "SHA-256" and c.props["signature_algorithm"] == "RSA"
    assert c.props["cn"] == "pay.zoo.local" and "zoo.local" in c.props["san"] and c.props["expired"] is False
    assert c.props["sha256_fingerprint"] and c.props["not_after"] > c.props["not_before"]
    algs = {(f.name, f.props.get("key_size")) for f in fs if f.asset_type == "algorithm" and f.location == "rsa2048_sha256.crt"}
    assert ("RSA", 2048) in algs and ("SHA-256", None) in algs


def test_expired_der_and_ecdsa(certs):
    out, _ = certs
    fs = _collect(out)
    exp = [f for f in fs if f.asset_type == "certificate" and f.location == "rsa2048_expired.crt"][0]
    assert exp.props["expired"] is True and exp.props["key_size"] == 2048 and exp.props["days_left"] < 0
    if "rsa1024_sha1.der" in certs[1]:
        sha1 = [f for f in fs if f.asset_type == "certificate" and f.location == "rsa1024_sha1.der"][0]
        assert sha1.props["key_size"] == 1024 and sha1.props["signature_hash"] == "SHA-1"
    ecc = [f for f in fs if f.asset_type == "certificate" and f.location == "ecdsa_p256.crt"][0]
    assert ecc.props["public_key_algorithm"] == "ECDSA" and ecc.props["curve"] == "secp256r1"
    bundle = [f for f in fs if f.asset_type == "certificate" and f.location == "bundle.pem"]
    assert len(bundle) == 2


def test_private_key_p12_jks(certs):
    out, truth = certs
    fs = _collect(out)
    key = [f for f in fs if f.asset_type == "related-crypto-material" and f.location == "rsa2048_sha256.key"][0]
    assert key.props["type"] == "private-key" and key.props["algorithm"] == "RSA" and key.props["key_size"] == 2048
    p12 = [f for f in fs if f.location == "pay.p12"]
    assert any(f.asset_type == "certificate" for f in p12) and any(f.props.get("type") == "private-key" for f in p12)
    if "keystore.jks" in truth:
        jks = [f for f in fs if f.location == "keystore.jks"]
        assert any(f.props.get("type") == "private-key" and f.props.get("algorithm") == "RSA" and f.props.get("key_size") == 2048 for f in jks)
        assert any(f.asset_type == "certificate" for f in jks)


def test_parse_x509_roundtrip(certs):
    out, _ = certs
    info = parse_x509((out / "ca_rsa4096.crt").read_bytes(), kb)
    assert info["is_ca"] is True and info["self_signed"] is True and info["key_size"] == 4096
