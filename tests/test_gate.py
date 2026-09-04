import copy

from ecdat.gate import compare


def _bom(assets):
    comps = []
    for name, comp, loc, qclass, exposure, usage, prim in assets:
        comps.append({"type": "cryptographic-asset", "bom-ref": f"ref:{name}:{loc}", "name": name,
                      "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": prim}},
                      "evidence": {"occurrences": [{"location": loc, "line": 1}]},
                      "properties": [{"name": "ecdat:component", "value": comp}, {"name": "ecdat:quantum_class", "value": qclass},
                                     {"name": "ecdat:exposure", "value": exposure}, {"name": "ecdat:usage", "value": usage},
                                     {"name": "ecdat:tier", "value": "ACT_NOW"}, {"name": "ecdat:recommendation", "value": "X25519MLKEM768"}]})
    return {"components": comps}


BASE = _bom([("AES-256", "app", "a.py", "safe", "internal", "security", "block-cipher"),
             ("RSA-2048", "app", "legacy.py", "broken", "internal", "security", "pke")])


def test_same_bom_passes():
    g = compare(BASE, copy.deepcopy(BASE))
    assert g.passed and not g.new_vulnerable and "PASS" in g.summary_md


def test_new_rsa_fails_but_old_is_grandfathered():
    cur = _bom([("AES-256", "app", "a.py", "safe", "internal", "security", "block-cipher"),
                ("RSA-2048", "app", "legacy.py", "broken", "internal", "security", "pke"),
                ("RSA-2048", "app", "new_feature.py", "broken", "external", "security", "pke")])
    g = compare(BASE, cur)
    assert not g.passed and len(g.new_vulnerable) == 1 and g.new_vulnerable[0]["location"] == "new_feature.py"
    assert "FAIL" in g.summary_md and "new_feature.py" in g.summary_md


def test_removal_passes_and_is_reported():
    cur = _bom([("AES-256", "app", "a.py", "safe", "internal", "security", "block-cipher")])
    g = compare(BASE, cur)
    assert g.passed and len(g.removed) == 1 and "Removed" in g.summary_md


def test_no_vulnerable_policy_fails_on_existing_debt():
    assert not compare(BASE, copy.deepcopy(BASE), "no-vulnerable").passed


def test_dst_m2_ignores_new_internal_hash_but_blocks_new_external_rsa():
    cur = _bom([("RSA-2048", "app", "legacy.py", "broken", "internal", "security", "pke"),
                ("MD5", "app", "x.py", "legacy-broken", "internal", "security", "hash")])
    assert compare(BASE, cur, "dst-m2").passed
    cur2 = _bom([("RSA-2048", "app", "legacy.py", "broken", "internal", "security", "pke"),
                 ("ECDH", "app", "edge.py", "broken", "external", "security", "key-agree")])
    assert not compare(BASE, cur2, "dst-m2").passed


def test_non_security_md5_is_not_blocking():
    cur = _bom([("RSA-2048", "app", "legacy.py", "broken", "internal", "security", "pke"),
                ("MD5", "app", "cache.py", "legacy-broken", "internal", "non-security", "hash")])
    assert compare(BASE, cur).passed
