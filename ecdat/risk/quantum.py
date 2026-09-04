"""Quantum vulnerability class + whether harvest-now-decrypt-later (HNDL) applies to this asset."""
from __future__ import annotations

from ecdat.enrich.exposure import CONFIDENTIALITY
from ecdat.knowledge import KnowledgeBase
from ecdat.model import CryptoAsset

LEGACY_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
PQ_GROUP_HINTS = ("MLKEM", "KYBER", "SNTRUP", "ML-KEM")
LIVE_USAGES = {"security", "unknown", "vendored", None, ""}


def _protocol_class(asset: CryptoAsset) -> tuple[str, str]:
    props = asset.props or {}
    versions = set(props.get("versions") or [])
    groups = [str(g).upper() for g in (props.get("kex_groups") or props.get("curves") or [])]
    negotiated = props.get("negotiated") or {}
    if props.get("pq_kex") or any(any(h in g for h in PQ_GROUP_HINTS) for g in groups) \
            or any(h in str(negotiated.get("kex_group", "")).upper() for h in PQ_GROUP_HINTS):
        return "safe", "post-quantum (hybrid) key exchange available"
    if versions & LEGACY_VERSIONS:
        return "legacy-broken", f"legacy protocol version(s) enabled: {', '.join(sorted(versions & LEGACY_VERSIONS))}"
    suites = props.get("cipher_suites") or []
    if any(("RC4" in s.upper() or "3DES" in s.upper() or "DES-CBC3" in s.upper() or "NULL" in s.upper() or "MD5" in s.upper()) for s in suites):
        return "legacy-broken", "legacy cipher suite(s) enabled"
    if versions or suites or negotiated or asset.evidence:
        return "broken", "classical (ECDHE/RSA) key exchange only: harvestable today"
    return "unknown", "no negotiation details"


def classify(asset: CryptoAsset, kb: KnowledgeBase) -> dict:
    props = asset.props or {}
    usage = (asset.context or {}).get("usage")
    if asset.asset_type == "protocol":
        qclass, reason = _protocol_class(asset)
        confidentiality = True
    else:
        name = asset.name
        if asset.asset_type == "certificate":
            name = props.get("public_key_algorithm") or name
        elif asset.asset_type == "related-crypto-material":
            name = props.get("algorithm") or name
        info = kb.info(name) if name else {}
        qclass = info.get("quantum", "unknown")
        reason = info.get("quantum_reason", "")
        # sized family placeholders (AES without a size) stay 'weakened' until a size is known
        if name == "AES" and props.get("key_size"):
            sized = kb.canonicalise("AES", props["key_size"])
            if sized:
                info = kb.info(sized)
                qclass, reason = info.get("quantum", qclass), info.get("quantum_reason", reason)
        # short RSA/DH/DSA keys are classically weak regardless of quantum
        ks = props.get("key_size") or asset.key_size
        min_ks = info.get("legacy_min_key_size")
        if ks and min_ks and ks < min_ks:
            qclass = "legacy-broken"
            reason = f"{ks}-bit key is below the classical minimum of {min_ks} bits"
        confidentiality = bool(info.get("confidentiality")) or (asset.primitive in CONFIDENTIALITY)
        if asset.asset_type == "certificate":
            confidentiality = bool((asset.exposure or {}).get("transit"))
        if asset.asset_type == "related-crypto-material":
            confidentiality = name in {"RSA", "X25519", "ECDH", "DH", "AES-128", "AES-256", "AES", "3DES", "DES"}
    exposure = asset.exposure or {}
    hndl = (qclass in ("broken", "weakened")
            and confidentiality
            and not exposure.get("signing_only")
            and bool(exposure.get("transit") or exposure.get("at_rest"))
            and usage in LIVE_USAGES)
    out = {"quantum_class": qclass, "reason": reason, "hndl_applicable": hndl, "confidentiality": confidentiality}
    asset.context["quantum_class"] = qclass
    asset.context["hndl_applicable"] = hndl
    return out


def apply(assets: list[CryptoAsset], kb: KnowledgeBase) -> None:
    for a in assets:
        classify(a, kb)
