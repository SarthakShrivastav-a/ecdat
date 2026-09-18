from ecdat.enrich.context import classify


def test_non_security_md5():
    c = classify("MD5", "hash", 'return hashlib.md5(url.encode()).hexdigest()  # etag cache key', "utils/cache.py", {})
    assert c["usage"] == "non-security"


def test_security_md5():
    c = classify("MD5", "hash", "digest = hashlib.md5(password.encode()).hexdigest()", "auth.py", {})
    assert c["usage"] == "security"


def test_test_and_comment_context():
    assert classify("SHA-1", "hash", "hashlib.sha1(b'x')", "tests/test_auth.py", {"is_test": True})["usage"] == "test"
    assert classify("RSA", "pke", "# we used RSA here", "a.py", {"in_comment": True})["usage"] == "comment"


def test_unknown_hash_is_conservative():
    assert classify("SHA-256", "hash", "h = hashlib.sha256(blob).hexdigest()", "x.py", {})["usage"] == "security"


def test_non_hash_primitive_is_security():
    assert classify("RSA", "pke", "rsa.generate_private_key(key_size=2048)", "a.py", {})["usage"] == "security"


def test_sha1_identifier_and_approved_constructions_are_not_flagged():
    from ecdat.enrich.context import classify
    skid = classify("SHA-1", "hash", "skid := sha1.Sum(spki.SubjectPublicKey.Bytes)", "cert.go", {})
    assert skid["usage"] == "non-security"
    oaep = classify("SHA-1", "hash", "padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)", "backend.py", {})
    assert oaep["usage"] == "non-security" and "OAEP" in oaep["reason"]
    pw = classify("SHA-1", "hash", "digest = hashlib.sha1(password).hexdigest()", "auth.py", {})
    assert pw["usage"] == "security"


def test_nist_pqc_reference_api_is_not_ed25519():
    import pathlib
    text = (pathlib.Path(__file__).parents[1] / "ecdat" / "knowledge" / "source_patterns.yaml").read_text(encoding="utf-8")
    assert "{callee: crypto_sign_keypair," not in text
    assert "crypto_sign_ed25519_keypair" in text


def test_non_standard_test_dirs_and_identifiers():
    from ecdat.collectors.base import path_context
    from ecdat.enrich.context import classify
    for p in ("caddytest/leafcert.pem", "certbot-compatibility-test/nginx/a.conf", "src/certbot_integration_tests/x.py",
              "pkg/testutil/keys.go", "test-fixtures/k.pem"):
        assert path_context(p)["is_test"], p
    for p in ("src/latest/app.py", "contest/main.go", "attest/sign.py"):
        assert not path_context(p)["is_test"], p
    fp = classify("SHA-1", "hash", "_thumb=\"$(_fingerprint \"$_ccert\" 'sha1')\"", "deploy/x.sh", {})
    assert fp["usage"] == "non-security"
