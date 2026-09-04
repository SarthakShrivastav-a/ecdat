"""CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM, HBOM v2.0 (9 Jul 2025), Table 9:
'Minimum Elements pertaining to Cryptographic Asset'. Completeness check per asset type."""
from __future__ import annotations

from ecdat.model import CryptoAsset

TABLE9 = {
    "algorithm": ["Name", "Asset Type", "Primitive", "Mode", "Crypto Functions", "Classical security level", "OID"],
    "key": ["Name", "Asset Type", "id", "state", "size", "Creation Date", "Activation Date"],
    "protocol": ["Name", "Asset Type", "Version", "Cipher Suites", "OID"],
    "certificate": ["Name", "Asset Type", "Subject Name", "Issuer Name", "Not Valid Before", "Not Valid After",
                    "Signature Algorithm Reference", "Subject Public Key Reference", "Certificate Format", "Certificate Extension"],
}
SOURCE = "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM v2.0 (09.07.2025), section 8.3 Table 9"


def _present_algorithm(a: CryptoAsset) -> dict:
    return {"Name": bool(a.name), "Asset Type": True, "Primitive": bool(a.primitive and a.primitive not in ("unknown", "other")),
            "Mode": bool(a.mode) or a.primitive in ("hash", "signature", "kdf", "mac", "kem", "key-agree", "pke", "combiner", "xof", "drbg"),
            "Crypto Functions": bool(a.crypto_functions), "Classical security level": a.classical_security_level is not None,
            "OID": bool(a.oid)}


def _present_key(a: CryptoAsset) -> dict:
    p = a.props
    return {"Name": bool(a.name), "Asset Type": True, "id": bool(p.get("id") or p.get("alias") or a.bom_ref), "state": bool(p.get("state")),
            "size": bool(a.key_size or p.get("key_size")), "Creation Date": bool(p.get("creation_date") or p.get("not_before")),
            "Activation Date": bool(p.get("activation_date") or p.get("not_before"))}


def _present_protocol(a: CryptoAsset) -> dict:
    p = a.props
    return {"Name": bool(a.name), "Asset Type": True, "Version": bool(p.get("versions")), "Cipher Suites": bool(p.get("cipher_suites")),
            "OID": bool(a.oid or p.get("oid"))}


def _present_certificate(a: CryptoAsset) -> dict:
    p = a.props
    return {"Name": bool(a.name), "Asset Type": True, "Subject Name": bool(p.get("subject")), "Issuer Name": bool(p.get("issuer")),
            "Not Valid Before": bool(p.get("not_before")), "Not Valid After": bool(p.get("not_after")),
            "Signature Algorithm Reference": bool(p.get("signature_algorithm_oid") or p.get("signature_algorithm")),
            "Subject Public Key Reference": bool(p.get("public_key_algorithm")), "Certificate Format": bool(p.get("format")),
            "Certificate Extension": bool(p.get("extension"))}


def completeness(a: CryptoAsset) -> dict:
    if a.asset_type == "certificate":
        table, present = "certificate", _present_certificate(a)
    elif a.asset_type == "protocol":
        table, present = "protocol", _present_protocol(a)
    elif a.asset_type == "related-crypto-material" and (a.props.get("type") or "").endswith("key"):
        table, present = "key", _present_key(a)
    elif a.asset_type == "algorithm":
        table, present = "algorithm", _present_algorithm(a)
    else:
        return {"table": None, "present": [], "missing": [], "pct": None}
    have = [k for k in TABLE9[table] if present.get(k)]
    miss = [k for k in TABLE9[table] if not present.get(k)]
    return {"table": table, "present": have, "missing": miss, "pct": round(100.0 * len(have) / len(TABLE9[table]), 1)}


def apply(assets: list[CryptoAsset]) -> None:
    for a in assets:
        a.certin = completeness(a)


def summary(assets: list[CryptoAsset]) -> dict:
    by: dict[str, list[float]] = {}
    missing: dict[str, int] = {}
    for a in assets:
        c = a.certin or completeness(a)
        if c.get("pct") is None:
            continue
        by.setdefault(c["table"], []).append(c["pct"])
        for m in c["missing"]:
            missing[f"{c['table']}:{m}"] = missing.get(f"{c['table']}:{m}", 0) + 1
    out = {"by_type": {k: round(sum(v) / len(v), 1) for k, v in by.items()}, "counts": {k: len(v) for k, v in by.items()},
           "top_missing": sorted(missing.items(), key=lambda kv: -kv[1])[:8], "source": SOURCE}
    allv = [x for v in by.values() for x in v]
    out["overall_pct"] = round(sum(allv) / len(allv), 1) if allv else None
    return out
