"""Context triage: is this crypto use security-relevant, test-only, vendored, or just a comment?
This is the documented failure mode of every regex scanner (MD5 as a cache key != MD5 as a password hash)."""
from __future__ import annotations

import re

NON_SECURITY = re.compile(
    r"(cache|etag|checksum|uuid|fingerprint|thumbprint|skid|subject[_-]?key[_-]?id|key[_-]?identifier|dedup|bucket|shard|hash[_-]?key|partition|filename|content[_-]?id|"
    r"idempoten|memo|not security|non-security|integrity of download|consistent[_-]?hash|bloom|ring)", re.I)
SECURITY = re.compile(
    r"(password|passwd|pwd|token|secret|sign|verify|auth|hmac|session|credential|cert|private[_-]?key|"
    r"encrypt|decrypt|cipher|jwt|otp|login|pan\b|card|kyc|tls|ssl|handshake)", re.I)
# fingerprints / thumbprints / key identifiers name a thing; they are identifiers even when computed over a cert
IDENTIFIER = re.compile(r"(fingerprint|thumbprint|skid|subject[_-]?key[_-]?id|key[_-]?identifier|etag|uuid)", re.I)
APPROVED_SHA1 = re.compile(r"(HMAC|OAEP|MGF1)", re.I)
HASHES = {"MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"}


def classify(name: str, primitive: str | None, snippet: str | None, location: str, context: dict) -> dict:
    """Return {"usage": security|non-security|test|comment|vendored|unknown, "reason": str}."""
    if context.get("in_comment"):
        return {"usage": "comment", "reason": "mentioned in a comment, not executed"}
    if context.get("is_test"):
        return {"usage": "test", "reason": "inside test code; not reachable in production"}
    text = f"{snippet or ''} {location}"
    if name == "SHA-1" and APPROVED_SHA1.search(snippet or ""):
        return {"usage": "non-security", "reason": "SHA-1 inside HMAC / OAEP / MGF1: collision resistance is not required, still an approved use"}
    if (primitive == "hash" or name in HASHES):
        ident = IDENTIFIER.search(text)
        if ident:
            return {"usage": "non-security", "reason": f"hash used as an identifier ({ident.group(1)}), not a security control"}
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
        ctx = dict(a.context)
        prod = [e for e in a.evidence if not e.context.get("is_test") and not e.context.get("in_comment")]
        ctx["is_test"] = bool(a.evidence) and not prod and all(e.context.get("is_test") for e in a.evidence)
        ctx["in_comment"] = bool(a.evidence) and not prod and all(e.context.get("in_comment") for e in a.evidence)
        ctx["is_vendored"] = bool(a.evidence) and all(e.context.get("is_vendored") for e in a.evidence)
        verdicts = []
        for e in (prod or a.evidence):
            ectx = dict(ctx)
            ectx.update({k: v for k, v in e.context.items() if k in ("is_test", "in_comment", "is_vendored")})
            if prod:
                ectx["is_test"] = False
                ectx["in_comment"] = False
            verdicts.append(classify(a.name, a.primitive, e.snippet, e.location, ectx))
        if not verdicts:
            verdicts = [classify(a.name, a.primitive, None, "", ctx)]
        order = ["security", "vendored", "non-security", "unknown", "test", "comment"]
        best = min(verdicts, key=lambda v: order.index(v["usage"]) if v["usage"] in order else len(order))
        a.context.update(ctx)
        a.context["usage"] = best["usage"]
        a.context["usage_reason"] = best["reason"]
        a.context["usage_votes"] = {u: sum(1 for v in verdicts if v["usage"] == u) for u in {v["usage"] for v in verdicts}}
