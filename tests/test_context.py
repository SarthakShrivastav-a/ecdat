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
