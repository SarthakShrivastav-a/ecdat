"""Regulatory overlays (DST India, NIST IR 8547, CNSA 2.0, CERT-In v2.0, EU, UK) driven by frameworks.yaml."""
from __future__ import annotations

from ecdat.knowledge import KnowledgeBase
from ecdat.model import CryptoAsset, ScanParams

NETWORK_HINT = ("nginx", "haproxy", "openssl.cnf", "sshd", "ipsec", "router", "vpn", "firewall", "edge", "lb", "gateway")


def _class(asset: CryptoAsset, kb: KnowledgeBase | None = None) -> str:
    q = (asset.risk.quantum_class if asset.risk else None) or asset.context.get("quantum_class")
    if (q is None or q == "unknown") and kb is not None:
        from ecdat.risk import quantum  # local import: quantum does not depend on frameworks
        q = quantum.classify(asset, kb)["quantum_class"]
    return q or "unknown"


def _usage_live(asset: CryptoAsset) -> bool:
    return asset.context.get("usage") not in ("non-security", "test", "comment")


def _is_pqc(asset: CryptoAsset, kb: KnowledgeBase) -> bool:
    return bool(kb.info(asset.name).get("pqc")) if asset.asset_type == "algorithm" else False


def overlays(asset: CryptoAsset, params: ScanParams, kb: KnowledgeBase) -> list[dict]:
    fw = kb.frameworks or {}
    out: list[dict] = []
    qclass = _class(asset, kb)
    live = _usage_live(asset)
    zone = (asset.exposure or {}).get("zone", "internal")
    vulnerable = qclass in ("broken", "legacy-broken") and live
    weakened = qclass == "weakened" and live

    # DST India -----------------------------------------------------------------------------------
    dst = fw.get("dst_india")
    if dst:
        prof = dst["profiles"].get(params.profile, dst["profiles"]["enterprise"])
        out.append({"framework": "DST-NQM", "rule": "M1 inventory", "status": "ok", "deadline_year": prof["M1"],
                    "text": "asset is inventoried in a CycloneDX CBOM (M1 requirement met for this asset)"})
        if vulnerable:
            out.append({"framework": "DST-NQM", "rule": "M2 no new classical-only deployments", "deadline_year": prof["M2"],
                        "status": "violation" if zone == "external" else "warning", "kind": "policy",
                        "text": f"classical-only {asset.name} must not be newly deployed after {prof['M2']} ({params.profile.upper()}); enforced by the CI gate"})
            out.append({"framework": "DST-NQM", "rule": "M3 quantum-safe-only trust chains", "deadline_year": prof["M3"],
                        "status": "violation", "text": f"{asset.name} must be migrated before {prof['M3']} ({params.profile.upper()})"})
        elif weakened:
            out.append({"framework": "DST-NQM", "rule": "M3 quantum-safe-only trust chains", "deadline_year": prof["M3"],
                        "status": "warning", "text": f"{asset.name} is Grover-weakened; upgrade parameters before {prof['M3']}"})

    # NIST IR 8547 -------------------------------------------------------------------------------
    nist = fw.get("nist_ir_8547")
    if nist and qclass == "broken" and live:
        out.append({"framework": "NIST IR 8547", "rule": "deprecate 2030 / disallow 2035", "deadline_year": nist["deprecate_year"],
                    "status": "violation", "text": f"{asset.name} deprecated after {nist['deprecate_year']}, disallowed after {nist['disallow_year']}"})
    if nist and qclass == "legacy-broken" and live:
        out.append({"framework": "NIST IR 8547", "rule": "already disallowed", "deadline_year": params.now_year,
                    "status": "violation", "text": f"{asset.name} is classically broken or below minimum strength; disallowed now"})

    # CNSA 2.0 -----------------------------------------------------------------------------------
    cnsa = fw.get("cnsa_2_0")
    if cnsa and live:
        loc = " ".join(e.location for e in asset.evidence).lower()
        is_network = any(h in loc for h in NETWORK_HINT) or asset.asset_type == "protocol"
        tl = cnsa["timelines"]["networking_equipment" if is_network else "web_browsers_servers_cloud"]
        if asset.name in ("AES-128", "AES-192"):
            out.append({"framework": "CNSA 2.0", "rule": f"AES >= {cnsa['aes_min_bits']}", "deadline_year": tl["exclusive"],
                        "status": "violation", "text": f"{asset.name} below CNSA 2.0 minimum AES-{cnsa['aes_min_bits']}"})
        if asset.name in ("SHA-256", "SHA-224") and asset.primitive == "hash":
            out.append({"framework": "CNSA 2.0", "rule": f"SHA >= {cnsa['hash_min_bits']}", "deadline_year": tl["exclusive"],
                        "status": "warning", "text": f"{asset.name} below CNSA 2.0 minimum SHA-{cnsa['hash_min_bits']} (for NSS use)"})
        if qclass == "broken":
            target = cnsa["signature_target"] if asset.primitive == "signature" else cnsa["kem_target"]
            out.append({"framework": "CNSA 2.0", "rule": "quantum-resistant only", "deadline_year": tl["exclusive"],
                        "status": "violation", "text": f"{asset.name} must be replaced by {target} (exclusive by {tl['exclusive']})"})
        if _is_pqc(asset, kb) and not kb.info(asset.name).get("cnsa") and not kb.info(asset.name).get("hybrid"):
            out.append({"framework": "CNSA 2.0", "rule": "parameter set", "deadline_year": tl["exclusive"], "status": "warning",
                        "text": f"{asset.name} is PQC but not the CNSA 2.0 parameter set ({cnsa['kem_target']} / {cnsa['signature_target']})"})

    # CERT-In v2.0 -------------------------------------------------------------------------------
    cert_in = fw.get("cert_in_v2")
    if cert_in and qclass == "legacy-broken" and live:
        out.append({"framework": "CERT-In v2.0", "rule": "8.4.2.2 prohibit weak/deprecated algorithms", "deadline_year": params.now_year,
                    "status": "violation", "text": f"{asset.name} is a weak or deprecated algorithm"})
    if cert_in and qclass == "broken" and live:
        out.append({"framework": "CERT-In v2.0", "rule": "8.5.1 transition off RSA/ECC/DH/DSA", "deadline_year": None,
                    "status": "warning", "text": f"{asset.name} is Shor-vulnerable; plan the transition (8.5.1)"})

    # EU / UK -------------------------------------------------------------------------------------
    eu = fw.get("eu_pqc")
    if eu and qclass == "broken" and live:
        yr = eu["high_risk_year"] if zone == "external" else eu["all_year"]
        out.append({"framework": "EU PQC roadmap", "rule": "high-risk by 2030 / all by 2035", "deadline_year": yr,
                    "status": "warning", "text": f"{asset.name} migration due by {yr} under the EU roadmap"})
    uk = fw.get("uk_ncsc")
    if uk and qclass == "broken" and live:
        out.append({"framework": "UK NCSC", "rule": "priority by 2031 / complete by 2035", "deadline_year": uk["priority_year"],
                    "status": "warning", "text": f"{asset.name} priority migration by {uk['priority_year']}"})
    return out


def earliest_deadline(over: list[dict]) -> int | None:
    """Earliest *migration* deadline (policy-type overlays such as DST M2 'no new deployments' are excluded)."""
    years = [o["deadline_year"] for o in over
             if o.get("deadline_year") and o.get("status") in ("violation", "warning") and o.get("kind", "migration") == "migration"]
    return min(years) if years else None


def apply(assets: list[CryptoAsset], params: ScanParams, kb: KnowledgeBase) -> None:
    for a in assets:
        ov = overlays(a, params, kb)
        if a.risk is not None:
            a.risk.overlays = ov
            a.risk.deadline_year = earliest_deadline(ov)
        a.context["overlays"] = ov
