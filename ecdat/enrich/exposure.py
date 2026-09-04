"""Exposure enrichment: where does this crypto sit, and can an adversary capture what it protects today?

  zone          internal | external (from the component / target)
  transit       protects data in flight (key exchange, TLS/SSH/IPsec, ciphers seen on the wire)
  at_rest       protects stored data (ciphers / public-key encryption in application code)
  signing_only  authentication / integrity only -> harvest-now-decrypt-later does NOT apply
"""
from __future__ import annotations

from ecdat.model import Component, CryptoAsset

CONFIDENTIALITY = {"pke", "kem", "key-agree", "block-cipher", "stream-cipher", "ae", "combiner"}
SIGNATURE_ALGS = {"ECDSA", "Ed25519", "DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA", "FN-DSA"}
WIRE_COLLECTORS = {"protocol", "pcap"}
WIRE_APIS = {"config", "constant", "x509-public-key", "x509-signature", "jks-private-key", "private-key"}


def assign(asset: CryptoAsset, component: Component | None = None) -> dict:
    zone = (component.zone if component else None) or asset.context.get("zone") or "internal"
    collectors = {e.collector for e in asset.evidence}
    props = asset.props or {}
    api = props.get("api") or ""
    primitive = asset.primitive
    function = props.get("function")
    reasons: list[str] = []

    transit = False
    at_rest = False
    signing_only = False

    if asset.asset_type == "protocol":
        transit = True
        reasons.append("protocol negotiation protects data in flight")
    elif asset.asset_type == "certificate":
        pk = props.get("public_key_algorithm")
        usage = props.get("key_usage") or []
        if pk == "RSA" and ("key_encipherment" in usage or not usage):
            transit = True
            reasons.append("RSA certificate key can do RSA key transport in TLS <= 1.2 (harvestable)")
        else:
            signing_only = True
            reasons.append("certificate key is used for authentication/signature only")
    elif asset.asset_type == "related-crypto-material":
        alg = props.get("algorithm")
        if alg in SIGNATURE_ALGS:
            signing_only = True
            reasons.append("signing key material")
        elif alg:
            at_rest = True
            reasons.append("private key material can decrypt stored or captured data")
    else:
        if collectors & WIRE_COLLECTORS or props.get("suite") or props.get("cipher_suites"):
            transit = True
            reasons.append("observed on the wire or in a cipher-suite configuration")
        if primitive in {"key-agree", "kem", "combiner"}:
            transit = True
            reasons.append("key exchange primitive")
        if primitive in {"block-cipher", "stream-cipher", "ae"} and not transit:
            at_rest = True
            reasons.append("symmetric cipher used in application code (stored data)")
        if primitive == "pke":
            if function in ("encrypt", "decrypt") or props.get("padding") in ("OAEP", "PKCS1v15"):
                at_rest = True
                reasons.append("public-key encryption of application data")
            elif api in ("x509-public-key", "config") or transit:
                transit = True
            else:
                # RSA keygen with unknown purpose: conservatively treat as encryption-capable
                at_rest = True
                reasons.append("RSA key with unspecified purpose; assumed encryption-capable (conservative)")
        if primitive == "signature" or asset.name in SIGNATURE_ALGS:
            signing_only = not (transit or at_rest)
            if signing_only:
                reasons.append("signature primitive: authenticity only, not confidentiality")
        if primitive in {"hash", "mac", "kdf", "drbg", "xof"}:
            signing_only = False
            reasons.append("integrity / derivation primitive; no confidentiality exposure")

    if zone == "external" and (transit or at_rest):
        reasons.append("internet-facing component: capturable today")

    out = {"zone": zone, "transit": transit, "at_rest": at_rest, "signing_only": signing_only,
           "confidentiality": bool(primitive in CONFIDENTIALITY) and not signing_only,
           "reason": "; ".join(reasons) or "no exposure signal"}
    asset.exposure = out
    return out


def apply(assets: list[CryptoAsset], components: list[Component]) -> None:
    by_ref = {c.bom_ref: c for c in components}
    by_name = {c.name: c for c in components}
    for a in assets:
        comp = by_ref.get(a.component) or by_name.get(a.component)
        assign(a, comp)
