"""Context triage: is this crypto use security-relevant, test-only, vendored, or just a comment?
This is the documented failure mode of every regex scanner (MD5 as a cache key != MD5 as a password hash)."""
from __future__ import annotations

import re

NON_SECURITY = re.compile(
    r"(cache|etag|checksum|uuid|fingerprint|dedup|bucket|shard|hash[_-]?key|partition|filename|content[_-]?id|"
    r"idempoten|memo|not security|non-security|integrity of download|consistent[_-]?hash|bloom|ring)", re.I)
SECURITY = re.compile(
    r"(password|passwd|pwd|token|secret|sign|verify|auth|hmac|session|credential|cert|private[_-]?key|"
    r"encrypt|decrypt|cipher|jwt|otp|login|pan\b|card|kyc|tls|ssl|handshake)", re.I)
HASHES = {"MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}


def classify(name: str, primitive: str | None, snippet: str | None, location: str, context: dict) -> dict:
    """Return {"usage": security|non-security|test|comment|vendored|unknown, "reason": str}."""
    if context.get("in_comment"):
        return {"usage": "comment", "reason": "mentioned in a comment, not executed"}
    if context.get("is_test"):
        return {"usage": "test", "reason": "inside test code; not reachable in production"}
    text = f"{snippet or ''} {location}"
    if (primitive == "hash" or name in HASHES):
        if NON_SECURITY.search(text) and not SECURITY.search(snippet or ""):
            return {"usage": "non-security", "reason": f"hash used for a non-security purpose ({NON_SECURITY.search(text).group(1)})"}
        if SECURITY.search(text):
            return {"usage": "security", "reason": f"hash used near a security concept ({SECURITY.search(text).group(1)})"}
        return {"usage": "security", "reason": "hash with unknown purpose; treated as security-relevant (conservative)"}
    if context.get("is_vendored"):
        return {"usage": "vendored", "reason": "inside vendored / third-party code"}
    return {"usage": "security", "reason": "cryptographic primitive in production code"}


def apply(assets: list) -> None:
    for a in assets:
        first = a.evidence[0] if a.evidence else None
        snippet = first.snippet if first else None
        ctx = dict(a.context)
        if first:
            for k in ("in_comment", "is_test", "is_vendored"):
                if first.context.get(k):
                    ctx[k] = True
        # if ANY evidence is production, the asset is production
        if any(not e.context.get("is_test") and not e.context.get("in_comment") for e in a.evidence):
            ctx["is_test"] = False
            ctx["in_comment"] = False
            snippet = next((e.snippet for e in a.evidence if not e.context.get("is_test") and not e.context.get("in_comment")), snippet)
        c = classify(a.name, a.primitive, snippet, first.location if first else "", ctx)
        a.context.update(ctx)
        a.context["usage"] = c["usage"]
        a.context["usage_reason"] = c["reason"]
