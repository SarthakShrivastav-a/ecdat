"""truth: SHA-1 inside test code (is_test context)."""
import hashlib


def test_legacy_digest():
    assert hashlib.sha1(b"x").hexdigest()
