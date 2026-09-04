from ecdat.enrich import agility, exposure
from ecdat.knowledge import KnowledgeBase
from ecdat.model import Component, CryptoAsset, Evidence, ScanParams, ScanResult
from ecdat.plan import optimizer, patches, pqc, vex
from ecdat.risk import mosca

kb = KnowledgeBase()


def _asset(name, primitive, snippet, loc="svc/a.py", line=5, asset_type="algorithm", x=10.0, props=None, usage="security", api=None,
           language="python", zone="external", n_files=1):
    ev = [Evidence("source", loc if i == 0 else f"svc/f{i}.py", line, snippet, "high", {}) for i in range(n_files)]
    p = {"api": api or snippet.split("(")[0], "language": language, "literal": True}
    p.update(props or {})
    a = CryptoAsset(bom_ref=f"ref-{name}-{loc}", asset_type=asset_type, name=name, primitive=primitive, component="svc", evidence=ev,
                    props=p, context={"usage": usage, "zone": zone}, lifetime_years=x, criticality_multiplier=1.0)
    exposure.assign(a, Component("c", "svc", zone=zone))
    agility.score(a, [], runtimes={"python": "3.11", "go": "1.22"}, kb=kb)
    mosca.assess(a, ScanParams(z_year=2035, now_year=2026, profile="cii"), kb)
    return a


def test_recommend_rsa_kex_hybrid_with_deltas():
    a = _asset("RSA", "pke", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", props={"key_size": 2048, "function": "keygen"})
    rec = pqc.recommend(a, kb)
    assert rec.target == "ML-KEM-768" and rec.alternative == "X25519MLKEM768" and rec.cnsa_target == "ML-KEM-1024"
    assert rec.hybrid is True and "FIPS 203" in rec.fips
    assert rec.deltas["pubkey_bytes"] == 1184 and "pubkey_bytes_vs_RSA" in rec.deltas and rec.deltas["latency_note"]
    assert rec.effort_weeks > 0 and "kyber" in rec.runtime_note.lower()


def test_recommend_ecdsa_and_hygiene():
    e = _asset("ECDSA", "signature", "key.sign(data, ec.ECDSA(hashes.SHA256()))")
    assert pqc.recommend(e, kb).target == "ML-DSA-65"
    md5 = _asset("MD5", "hash", "h = hashlib.md5(password.encode()).hexdigest()")
    r = pqc.recommend(md5, kb)
    assert r.target == "SHA-256" and "not PQC" in r.rationale
    safe = _asset("AES-256", "block-cipher", "AESGCM(key)")
    assert pqc.recommend(safe, kb).target is None and pqc.recommend(safe, kb).effort_weeks == 0.0
    aes128 = _asset("AES-128", "block-cipher", "AES_set_encrypt_key(k, 128, aes)", language="c", props={"key_size": 128})
    assert pqc.recommend(aes128, kb).target == "AES-256"
    kex = _asset("ECDH", "key-agree", "ssl_ecdh_curve prime256v1;", loc="nginx.conf", api="config", language=None)
    r = pqc.recommend(kex, kb)
    assert r.target == "X25519MLKEM768" and "Groups" in r.runtime_note


def test_plan_respects_budget_and_orders_by_risk_per_week():
    assets = [
        _asset("RSA", "pke", "rsa.generate_private_key(key_size=2048)", props={"key_size": 2048, "function": "encrypt"}, n_files=6, x=25),
        _asset("ECDH", "key-agree", "ssl_ecdh_curve prime256v1;", loc="nginx.conf", api="config", language=None, x=10),
        _asset("MD5", "hash", "hashlib.md5(password)", x=1),
        _asset("AES-256", "block-cipher", "AESGCM(key)"),
        _asset("ECDSA", "signature", "ec.ECDSA(hashes.SHA256())", x=7),
    ]
    for a in assets:
        pqc.recommend(a, kb)
    p = optimizer.plan(assets, engineers=1, months=1)     # ~4.3 weeks: cannot fit everything
    assert p["capacity_weeks"] == 4.3 and p["used_weeks"] <= p["capacity_weeks"]
    assert p["items"] and p["uncovered"], "small budget must leave something uncovered"
    ratios = [it["risk_per_week"] for it in p["items"]]
    assert ratios == sorted(ratios, reverse=True)
    assert all("AES-256" != it["name"] for it in p["items"] + p["uncovered"]), "SAFE assets are not planned"
    big = optimizer.plan(assets, engineers=4, months=6)
    assert big["covered_pct"] == 100.0 and not big["uncovered"]
    assert big["items"][-1]["cumulative_weeks"] <= big["capacity_weeks"]


def test_vex_and_patches():
    assets = [
        _asset("RSA", "pke", "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", props={"key_size": 2048, "function": "keygen"}),
        _asset("SHA-1", "hash", "hashlib.sha1(b'x')", loc="tests/test_x.py", usage="test"),
        _asset("AES-256", "block-cipher", "AESGCM(key)"),
        _asset("ECDH", "key-agree", "ssl_ecdh_curve prime256v1;", loc="nginx.conf", api="config", language=None),
    ]
    for a in assets:
        pqc.recommend(a, kb)
    patches.apply(assets)
    res = ScanResult(name="t", assets=assets, params=ScanParams(z_year=2035))
    v = vex.build(res)
    ids = {x["id"] for x in v["vulnerabilities"]}
    assert len(v["vulnerabilities"]) == 3 and all(i.startswith("ECDAT-QV-") for i in ids)
    states = {x["affects"][0]["ref"]: x["analysis"]["state"] for x in v["vulnerabilities"]}
    assert states[assets[0].bom_ref] == "exploitable" and states[assets[1].bom_ref] == "not_affected"
    assert assets[0].vex == "affected" and assets[1].vex == "not_affected"
    rsa_patches = assets[0].recommendation.patches
    assert rsa_patches and "ML_KEM_768" in rsa_patches[0]["unified_diff"] and rsa_patches[0]["unified_diff"].startswith("--- a/svc/a.py")
    nginx = assets[3].recommendation.patches
    assert nginx and "X25519MLKEM768" in nginx[0]["unified_diff"]
