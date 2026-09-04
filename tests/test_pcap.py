from pathlib import Path

import pytest

from ecdat.collectors.base import Target
from ecdat.collectors.pcap import PcapCollector
from ecdat.knowledge import KnowledgeBase

kb = KnowledgeBase()


@pytest.fixture(scope="module")
def pcaps(tmp_path_factory):
    from scripts.build_zoo import build_certs, build_pcaps
    base = tmp_path_factory.mktemp("zoo")
    build_certs(base / "certs")
    truth = build_pcaps(base / "pcaps", base / "certs")
    return base / "pcaps", truth


def test_https_handshake(pcaps):
    d, truth = pcaps
    fs = PcapCollector().collect(Target("pcap", str(d / "tls_handshake.pcap"), "capture", "external"), kb)
    proto = [f for f in fs if f.asset_type == "protocol"][0]
    assert proto.props["negotiated"]["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert proto.props["versions"] == ["TLSv1.2"] and proto.props["sni"] == "pay.zoo.local" and proto.props["starttls"] is False
    assert "x25519" in proto.props["offered_groups"]
    cert = [f for f in fs if f.asset_type == "certificate"][0]
    assert cert.props["cn"] == "pay.zoo.local"
    names = {f.name for f in fs if f.asset_type == "algorithm"}
    assert {"ECDH", "RSA", "AES-256", "SHA-384"} <= names
    assert all(f.location.startswith("pcap://tls_handshake.pcap#") for f in fs)


def test_smtp_starttls_legacy(pcaps):
    d, truth = pcaps
    fs = PcapCollector().collect(Target("pcap", str(d / "smtp_starttls.pcap"), "mail", "external"), kb)
    proto = [f for f in fs if f.asset_type == "protocol"][0]
    assert proto.props["starttls"] is True and proto.props["app_protocol"] == "smtp"
    assert proto.props["negotiated"]["cipher_suite"] == "TLS_RSA_WITH_3DES_EDE_CBC_SHA" and proto.props["versions"] == ["TLSv1.0"]
    names = {f.name for f in fs if f.asset_type == "algorithm"}
    assert "3DES" in names and "RSA" in names and "SHA-1" in names
