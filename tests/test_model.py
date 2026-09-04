from ecdat.model import RawFinding, ScanParams, CryptoAsset, Evidence, bump


def test_rawfinding_roundtrip():
    f = RawFinding(collector="source", asset_type="algorithm", name="RSA", location="a.py", line=3,
                   snippet="rsa.generate_private_key(key_size=2048)", confidence="high",
                   component="app", props={"key_size": 2048}, context={"is_test": False})
    d = f.to_dict()
    assert d["props"]["key_size"] == 2048 and d["confidence"] == "high"
    assert f.evidence().collector == "source"


def test_scanparams_defaults():
    p = ScanParams()
    assert p.z_year == 2041 and p.engineers == 4 and p.z_years == 15.0


def test_asset_to_dict_nested():
    a = CryptoAsset(bom_ref="x", asset_type="algorithm", name="RSA",
                    evidence=[Evidence("source", "a.py", 1, None, "high")])
    d = a.to_dict()
    assert d["evidence"][0]["location"] == "a.py"


def test_bump():
    assert bump("low") == "medium" and bump("high") == "high"
