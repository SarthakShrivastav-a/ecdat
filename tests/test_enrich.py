from ecdat.enrich import agility, exposure, lifetime
from ecdat.knowledge import KnowledgeBase
from ecdat.model import Component, CryptoAsset, Evidence

kb = KnowledgeBase()


def _ev(loc, line, snippet, collector="source"):
    return Evidence(collector, loc, line, snippet, "high", {})


def _rsa(n_files=1, sites=1, api="rsa.generate_private_key", literal=True, language="python", component="payments-api"):
    ev = []
    for f in range(n_files):
        for s in range(sites):
            ev.append(_ev(f"payments/mod{f}.py", 10 + s, "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)"))
    return CryptoAsset(bom_ref="a-rsa", asset_type="algorithm", name="RSA", primitive="pke", key_size=2048, component=component,
                       evidence=ev, props={"api": api, "key_size": 2048, "literal": literal, "language": language, "function": "keygen"},
                       context={"zone": "external"})


def test_exposure_rsa_keygen_at_rest_and_signature_signing_only():
    a = _rsa()
    ex = exposure.assign(a, Component("c1", "payments-api", zone="external"))
    assert ex["zone"] == "external" and ex["at_rest"] is True and ex["signing_only"] is False and ex["confidentiality"] is True
    sig = CryptoAsset(bom_ref="a-ecdsa", asset_type="algorithm", name="ECDSA", primitive="signature", component="payments-api",
                      evidence=[_ev("payments/auth.py", 20, "key.sign(data, ec.ECDSA(hashes.SHA256()))")], props={"api": "ec.ECDSA"})
    ex2 = exposure.assign(sig, Component("c1", "payments-api", zone="internal"))
    assert ex2["signing_only"] is True and ex2["confidentiality"] is False and ex2["transit"] is False


def test_exposure_protocol_and_hash():
    proto = CryptoAsset(bom_ref="p1", asset_type="protocol", name="TLS", primitive="other", component="edge-lb",
                        evidence=[_ev("nginx.conf", 7, "ssl_protocols TLSv1.2 TLSv1.3;")], props={"api": "config", "type": "tls", "versions": ["TLSv1.2"]})
    assert exposure.assign(proto, Component("c2", "edge-lb", zone="external"))["transit"] is True
    h = CryptoAsset(bom_ref="h1", asset_type="algorithm", name="SHA-256", primitive="hash", component="x", evidence=[_ev("a.py", 1, "hashlib.sha256(b)")])
    ex = exposure.assign(h, None)
    assert ex["transit"] is False and ex["at_rest"] is False and ex["confidentiality"] is False


def test_lifetime_inference():
    a = _rsa()
    years, cls, reason = lifetime.infer(Component("c1", "payments-api", zone="external"), a, kb)
    assert cls == "financial" and years == 10.0 and a.lifetime_years == 10.0
    years, cls, _ = lifetime.infer(Component("c1", "svc", zone="external", data_class="health"), a, kb)
    assert cls == "health" and years == 25.0
    b = CryptoAsset(bom_ref="b", asset_type="algorithm", name="AES-256", primitive="block-cipher", component="thing",
                    evidence=[_ev("core/util.py", 3, "AESGCM(key)")])
    years, cls, _ = lifetime.infer(Component("c9", "thing", zone="internal"), b, kb)
    assert cls == "generic" and years == 5.0
    # most conservative class wins when several hints match
    c = CryptoAsset(bom_ref="c", asset_type="algorithm", name="RSA", primitive="pke", component="portal",
                    evidence=[_ev("patient/session.py", 3, "rsa.generate_private_key(key_size=2048)")])
    assert lifetime.infer(Component("c3", "portal"), c, kb)[1] == "health"


def test_criticality_multiplier():
    assert lifetime.criticality_multiplier("low", kb) == 0.8
    assert lifetime.criticality_multiplier("critical", kb) == 1.5
    assert lifetime.criticality_multiplier(None, kb) == 1.0
    assert lifetime.criticality_multiplier("nonsense", kb) == 1.0


def test_agility_hardcoded_spread_vs_config():
    rigid = _rsa(n_files=8, sites=5)
    rigid_score = agility.score(rigid, [rigid], runtimes={"python": "3.11"}, kb=kb)
    cfg = CryptoAsset(bom_ref="cfg", asset_type="algorithm", name="ECDH", primitive="key-agree", component="edge-lb",
                      evidence=[_ev("nginx.conf", 9, "ssl_ecdh_curve prime256v1;")], props={"api": "config", "curve": "prime256v1"})
    cfg_score = agility.score(cfg, [cfg], runtimes=None, kb=kb)
    assert rigid_score.total < cfg_score.total
    assert rigid_score.y_years > cfg_score.y_years and cfg_score.y_years == 0.5
    assert set(rigid_score.dimensions) == set(agility.WEIGHTS)
    assert 0 <= rigid_score.total <= 100 and rigid_score.reasons


def test_agility_runtime_pqc_and_certificate():
    go_old = _rsa(api="rsa.GenerateKey", language="go")
    go_new = _rsa(api="rsa.GenerateKey", language="go")
    old = agility.score(go_old, [], runtimes={"go": "1.22"}, kb=kb)
    new = agility.score(go_new, [], runtimes={"go": "1.24"}, kb=kb)
    assert new.dimensions["runtime_pqc"] == 0.0 and old.dimensions["runtime_pqc"] > 0.0 and new.total > old.total
    cert = CryptoAsset(bom_ref="crt", asset_type="certificate", name="pay.zoo.local", component="pki",
                       evidence=[_ev("rsa2048.crt", None, "CN=pay.zoo.local", "certificate")], props={"public_key_algorithm": "RSA", "key_size": 2048})
    assert agility.score(cert, [], kb=kb).y_years == 0.5
    bin_only = CryptoAsset(bom_ref="bin", asset_type="algorithm", name="AES", primitive="block-cipher", component="fw",
                           evidence=[_ev("libcrypto.so", None, "AES S-box", "binary")], props={"api": "yara"}, context={"best_effort": True})
    b = agility.score(bin_only, [], kb=kb)
    assert b.dimensions["ownership"] == 1.0 and b.y_years >= 2.0
