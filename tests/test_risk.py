from ecdat.enrich import agility, exposure, lifetime
from ecdat.knowledge import KnowledgeBase
from ecdat.model import AgilityScore, Component, CryptoAsset, Evidence, ScanParams, ScanResult
from ecdat.risk import frameworks, mosca, quantum

kb = KnowledgeBase()


def _asset(name, primitive, asset_type="algorithm", zone="external", usage="security", x=10.0, y=3.0, props=None, **kw):
    a = CryptoAsset(bom_ref=f"ref-{name}-{x}-{zone}", asset_type=asset_type, name=name, primitive=primitive, component="svc",
                    evidence=[Evidence("source", "svc/main.py", 5, f"{name} usage", "high", {})], props=props or {},
                    context={"usage": usage, "zone": zone}, lifetime_years=x, criticality_multiplier=1.0,
                    agility=AgilityScore(total=50, y_years=y), **kw)
    exposure.assign(a, Component("c", "svc", zone=zone))
    return a


def test_rsa_kex_exposed_vs_act_now_by_z():
    a = _asset("RSA", "pke", x=10, y=3, props={"function": "encrypt", "padding": "OAEP"})
    r = mosca.assess(a, ScanParams(z_year=2035, now_year=2026), kb)   # Z = 9 < 13
    assert r.tier == "EXPOSED" and r.hndl_applicable and r.mosca_gap == 4.0
    r2 = mosca.assess(a, ScanParams(z_year=2041, now_year=2026), kb)  # Z = 15 > 13 by 2 -> margin small -> ACT_NOW
    assert r2.tier in ("ACT_NOW", "MONITOR") and r2.tier != "EXPOSED"
    r3 = mosca.assess(_asset("RSA", "pke", x=1, y=1, props={"function": "encrypt"}), ScanParams(z_year=2041, now_year=2026), kb)
    assert r3.tier == "MONITOR"


def test_signature_never_exposed_but_deadline_driven():
    sig = _asset("ECDSA", "signature", x=25, y=3)
    assert sig.exposure["signing_only"] is True
    r = mosca.assess(sig, ScanParams(z_year=2032, now_year=2026, profile="cii"), kb)
    assert r.hndl_applicable is False and r.tier != "EXPOSED"
    assert r.tier == "ACT_NOW" and r.deadline_year == 2029   # DST CII M3 (M2 is a deployment policy, not a migration deadline)
    assert any("harvest-now-decrypt-later does not apply" in s for s in r.reasons)


def test_non_security_and_safe():
    md5 = _asset("MD5", "hash", usage="non-security")
    assert mosca.assess(md5, ScanParams(), kb).tier == "SAFE"
    md5s = _asset("MD5", "hash", usage="security")
    r = mosca.assess(md5s, ScanParams(), kb)
    assert r.tier == "ACT_NOW" and r.quantum_class == "legacy-broken"
    aes = _asset("AES-256", "block-cipher")
    assert mosca.assess(aes, ScanParams(), kb).tier == "SAFE"
    kem = _asset("ML-KEM-768", "kem")
    assert mosca.assess(kem, ScanParams(), kb).tier == "SAFE"


def test_short_key_is_legacy_broken():
    a = _asset("RSA", "pke", props={"key_size": 1024, "function": "encrypt"})
    q = quantum.classify(a, kb)
    assert q["quantum_class"] == "legacy-broken"


def test_cnsa_flags_aes128_and_overlays_shape():
    a = _asset("AES-128", "block-cipher")
    ov = frameworks.overlays(a, ScanParams(profile="cii"), kb)
    cnsa = [o for o in ov if o["framework"] == "CNSA 2.0"]
    assert cnsa and cnsa[0]["status"] == "violation"
    rsa = _asset("RSA", "pke", props={"function": "encrypt"})
    ov = frameworks.overlays(rsa, ScanParams(profile="cii"), kb)
    fws = {o["framework"] for o in ov}
    assert {"DST-NQM", "NIST IR 8547", "CNSA 2.0", "CERT-In v2.0"} <= fws
    assert frameworks.earliest_deadline(ov) == 2029
    assert any(o["rule"].startswith("M2") and o.get("kind") == "policy" for o in ov)
    for o in ov:
        assert set(o) >= {"framework", "rule", "status", "deadline_year", "text"}


def test_protocol_classification():
    legacy = _asset("TLS", "other", asset_type="protocol", props={"type": "tls", "versions": ["TLSv1.0", "TLSv1.2"]})
    assert quantum.classify(legacy, kb)["quantum_class"] == "legacy-broken"
    pq = _asset("TLS", "other", asset_type="protocol", props={"type": "tls", "versions": ["TLSv1.3"], "pq_kex": True})
    assert quantum.classify(pq, kb)["quantum_class"] == "safe"
    classical = _asset("TLS", "other", asset_type="protocol", props={"type": "tls", "versions": ["TLSv1.3"], "kex_groups": ["x25519"]})
    q = quantum.classify(classical, kb)
    assert q["quantum_class"] == "broken" and q["hndl_applicable"] is True


def test_priority_and_recompute_moves_tiers():
    assets = [_asset("RSA", "pke", x=10, y=3, props={"function": "encrypt"}),
              _asset("ECDH", "key-agree", x=7, y=2),
              _asset("AES-256", "block-cipher"),
              _asset("RSA", "pke", x=30, y=5, props={"function": "encrypt"}, zone="internal")]
    res = ScanResult(name="t", assets=assets, params=ScanParams(z_year=2041, now_year=2026))
    mosca.recompute(res, ScanParams(z_year=2041, now_year=2026), kb)
    exposed_far = res.stats["tiers"]["EXPOSED"]
    mosca.recompute(res, ScanParams(z_year=2032, now_year=2026), kb)
    exposed_near = res.stats["tiers"]["EXPOSED"]
    assert exposed_near > exposed_far
    ext = [a for a in res.assets if a.name == "RSA" and a.exposure["zone"] == "external"][0]
    assert ext.risk.priority > 0
    assert res.stats["z_year"] == 2032 and res.stats["assets"] == 4


def test_library_capability_only_never_drives_act_now_or_plan():
    # the dependency *can* provide 3DES / RSA, but no use was observed in the codebase
    tdes = _asset("3DES", "block-cipher", x=10, y=3)
    tdes.context.update({"from_library_only": True, "corroborated": False})
    r = mosca.assess(tdes, ScanParams(z_year=2041, now_year=2026), kb)
    assert r.tier == "MONITOR"
    assert r.priority == 0.0
    assert any("library capability only" in s for s in r.reasons)
    # the same algorithm seen in code keeps its real tier
    seen = _asset("3DES", "block-cipher", x=10, y=3)
    assert mosca.assess(seen, ScanParams(z_year=2041, now_year=2026), kb).tier == "ACT_NOW"
    # corroborated by another collector: real use, real tier
    corr = _asset("3DES", "block-cipher", x=10, y=3)
    corr.context.update({"from_library_only": True, "corroborated": True})
    assert mosca.assess(corr, ScanParams(z_year=2041, now_year=2026), kb).tier == "ACT_NOW"
    assert mosca.summarize([tdes, seen])["library_capability_only"] == 1
