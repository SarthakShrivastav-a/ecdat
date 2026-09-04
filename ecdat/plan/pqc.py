"""PQC / hygiene recommendations with the deltas the PS asks for (latency, size, cost) and an effort estimate."""
from __future__ import annotations

from ecdat.knowledge import KnowledgeBase
from ecdat.model import CryptoAsset, Recommendation, ScanParams

LANG_KEY = {"python": "python", "javascript": "javascript", "java": "java", "go": "go", "c": "c"}
CLASSICAL_SIZES = {  # for the delta table
    "X25519": {"pubkey_bytes": 32, "ciphertext_bytes": 32}, "ECDH": {"pubkey_bytes": 65, "ciphertext_bytes": 65},
    "DH": {"pubkey_bytes": 256, "ciphertext_bytes": 256}, "RSA": {"pubkey_bytes": 270, "ciphertext_bytes": 256, "signature_bytes": 256},
    "ECDSA": {"pubkey_bytes": 65, "signature_bytes": 64}, "Ed25519": {"pubkey_bytes": 32, "signature_bytes": 64},
    "DSA": {"pubkey_bytes": 256, "signature_bytes": 64},
}


def _rule_for(asset: CryptoAsset, qclass: str, kb: KnowledgeBase, name: str) -> dict | None:
    prim = asset.primitive
    for rule in (kb.pqc.get("rules") or []):
        if "from_name" in rule and name in rule["from_name"]:
            return rule
        if "from_primitive" in rule and prim in rule["from_primitive"] and qclass in rule.get("from_class", []):
            return rule
    return None


def _effective_name(asset: CryptoAsset) -> str:
    props = asset.props or {}
    if asset.asset_type == "certificate":
        return props.get("public_key_algorithm") or asset.name
    if asset.asset_type == "related-crypto-material":
        return props.get("algorithm") or asset.name
    return asset.name


def effort_weeks(asset: CryptoAsset, kb: KnowledgeBase) -> float:
    base_tbl = kb.pqc.get("effort_base_weeks") or {}
    api = (asset.props or {}).get("api")
    if api == "config":
        base = float(base_tbl.get("config", 1.0))
    else:
        base = float(base_tbl.get(asset.asset_type, 2.0))
    total = asset.agility.total if asset.agility else 50
    files = len({e.location for e in asset.evidence}) or 1
    spread_factor = 1.0 + min(files, 10) / 10.0
    return round(base * (1 + (100 - total) / 25.0) * spread_factor, 1)


def recommend(asset: CryptoAsset, kb: KnowledgeBase, params: ScanParams | None = None) -> Recommendation:
    params = params or ScanParams()
    qclass = (asset.risk.quantum_class if asset.risk else None) or asset.context.get("quantum_class") or kb.info(_effective_name(asset)).get("quantum", "unknown")
    name = _effective_name(asset)
    targets = kb.pqc.get("targets") or {}
    lang = (asset.props or {}).get("language")
    rt_key = "config" if (asset.props or {}).get("api") == "config" or asset.asset_type in ("protocol",) else LANG_KEY.get(lang or "", None)
    rt = (kb.pqc.get("runtime_support") or {}).get(rt_key or "", {})

    if asset.asset_type == "protocol":
        rec = Recommendation(target="X25519MLKEM768", alternative="ML-KEM-768", cnsa_target="ML-KEM-1024", fips=["FIPS 203"],
                             hybrid=True, deltas=dict(targets.get("X25519MLKEM768", {})),
                             runtime_note=rt.get("kem", "enable a PQ hybrid group on the TLS terminator (OpenSSL >= 3.5)"),
                             rationale="enable hybrid PQ key exchange on the wire; keep classical suites for clients that lack it")
        if qclass == "safe":
            rec.rationale = "PQ key exchange already negotiated; monitor for parameter changes"
            rec.effort_weeks = 0.0
        elif qclass == "legacy-broken":
            rec.rationale = "disable legacy protocol versions / suites, then enable X25519MLKEM768"
        rec.effort_weeks = rec.effort_weeks or effort_weeks(asset, kb)
        asset.recommendation = rec
        return rec

    if asset.asset_type == "certificate":
        pr = asset.props or {}
        pk = pr.get("public_key_algorithm")
        pk_class = kb.info(pk).get("quantum", "unknown") if pk else "unknown"
        if pk_class == "safe":
            rec = Recommendation(target=None, rationale="certificate already uses a quantum-safe public key", effort_weeks=0.0)
        else:
            legacy = pr.get("expired") or (pr.get("key_size") and pk == "RSA" and pr["key_size"] < 2048) or pr.get("signature_hash") in ("SHA-1", "MD5")
            rec = Recommendation(target="ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)",
                                 alternative="SLH-DSA-SHA2-128s certificate", cnsa_target="ML-DSA-87 certificate", fips=["FIPS 204"],
                                 deltas=dict(targets.get("ML-DSA-65", {})), hybrid=True,
                                 runtime_note="until PQC certificates are issuable: shorten validity, automate rotation, pin the trust chain",
                                 rationale=("re-issue now: expired, sub-2048-bit or SHA-1/MD5-signed certificate" if legacy else
                                            f"{pk}-{pr.get('key_size') or ''} public key is Shor-vulnerable; plan re-issuance with a PQC signature algorithm"))
        rec.effort_weeks = rec.effort_weeks if rec.target is None else effort_weeks(asset, kb)
        asset.recommendation = rec
        return rec

    if qclass == "safe" or asset.context.get("usage") in ("non-security", "test", "comment"):
        rec = Recommendation(target=None, rationale="no change required" if qclass == "safe" else f"{asset.context.get('usage')} use; no migration needed",
                             effort_weeks=0.0)
        if name in ("AES-128", "AES-192") or (name == "AES" and not (asset.props or {}).get("key_size")):
            pass
        asset.recommendation = rec
        return rec

    rule = _rule_for(asset, qclass, kb, name)
    if rule is None:
        rec = Recommendation(target=None, rationale=f"no mapping rule for {name} ({asset.primitive}, {qclass}); review manually",
                             effort_weeks=effort_weeks(asset, kb))
        asset.recommendation = rec
        return rec

    target = rule["to"]
    tinfo = targets.get(target, {})
    deltas = {k: v for k, v in tinfo.items() if k in ("pubkey_bytes", "ciphertext_bytes", "signature_bytes", "key_bytes", "nist_level", "latency_note", "supported_by")}
    classical = CLASSICAL_SIZES.get(name, {})
    for k in ("pubkey_bytes", "ciphertext_bytes", "signature_bytes"):
        if k in deltas and k in classical:
            deltas[f"{k}_vs_{name}"] = f"{classical[k]} B -> {deltas[k]} B ({deltas[k] / max(classical[k], 1):.0f}x)"
    hybrid = bool(rule.get("hybrid")) and bool(tinfo.get("hybrid", rule.get("hybrid")))
    prim_key = "sig" if asset.primitive == "signature" else "kem"
    runtime_note = rt.get(prim_key) or ("native" if rt.get("native") else "add a PQC library")
    if rt.get("native_from"):
        runtime_note = f"native from {rt_key} {rt['native_from']}: {runtime_note}"
    rationale = rule.get("note") or f"{name} is {qclass}; {target} is the NIST-standardised replacement"
    if hybrid:
        rationale += "; deploy hybrid first (classical + PQ) so nothing gets weaker during transition"
    rec = Recommendation(target=target, alternative=rule.get("alt"), cnsa_target=rule.get("cnsa"), fips=list(tinfo.get("fips", [])),
                         deltas=deltas, runtime_note=runtime_note, effort_weeks=effort_weeks(asset, kb), hybrid=hybrid,
                         rationale=rationale)
    asset.recommendation = rec
    return rec


def apply(assets: list[CryptoAsset], kb: KnowledgeBase, params: ScanParams | None = None) -> None:
    for a in assets:
        recommend(a, kb, params)
