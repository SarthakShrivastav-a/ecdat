"""truth: MD5 used as a cache/etag key (non-security use)."""
import hashlib


def cache_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()  # etag cache key, not security


def content_fingerprint(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()
