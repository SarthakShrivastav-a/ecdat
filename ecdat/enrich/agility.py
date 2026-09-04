"""Crypto-agility per asset: how hard is this to change?

Seven dimensions adapted from the application-level crypto-agility assessment framework
(arXiv:2606.13425): each is 0..1 where 1 = rigid. total = 100 * (1 - weighted mean) so 100 = fully agile.
The dimensions are reported with reasons; the single number is a convenience, not a claim of precision.
"""
from __future__ import annotations

import re

from ecdat.knowledge import KnowledgeBase
from ecdat.model import AgilityScore, CryptoAsset

WEIGHTS = {
    "algorithm_coupling": 0.15, "provider_coupling": 0.15, "parameter_coupling": 0.10, "decoupling": 0.15,
    "spread": 0.15, "ownership": 0.15, "runtime_pqc": 0.15,
}
LOW_LEVEL_API = re.compile(r"(hazmat|javax\.crypto|java\.security|Cipher\.getInstance|KeyPairGenerator|Signature\.getInstance|"
                           r"MessageDigest|crypto/|rsa\.|ecdsa\.|aes\.|createCipheriv|createHash|generateKeyPair|"
                           r"RSA_|AES_|EVP_|MD5_|SHA\d*_|mbedtls_|forge\.|CryptoJS|hashlib|hashes\.)", re.I)
WRAPPER_API = re.compile(r"(jwt|jose|spring|passlib|bcrypt|argon2|nacl|sodium|ssl\.|requests|urllib|tls\.Config|SSLContext)", re.I)
RUNTIME_KEYS = {"python": "python", "javascript": "node", "java": "java", "go": "go", "c": "c"}


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3]) or (0,)


def _runtime_pqc(asset: CryptoAsset, runtimes: dict | None, kb: KnowledgeBase | None) -> tuple[float, str]:
    lang = (asset.props or {}).get("language")
    rt_key = RUNTIME_KEYS.get(lang or "", lang)
    table = (kb.libraries.get("runtimes") if kb else None) or {}
    info = table.get(rt_key or "", {})
    have = (runtimes or {}).get(rt_key or "")
    if info.get("pqc_native_from"):
        if have and _version_tuple(have) >= _version_tuple(info["pqc_native_from"]):
            return 0.0, f"{rt_key} {have} ships native PQC (>= {info['pqc_native_from']})"
        if have:
            return 0.5, f"{rt_key} {have} predates native PQC ({info['pqc_native_from']}); upgrade or add a PQC library"
        return 0.4, f"{rt_key} has native PQC from {info['pqc_native_from']}; runtime version unknown"
    if info.get("pqc_native"):
        return 0.0, f"{rt_key} ships native PQC"
    if rt_key in ("python", "node"):
        return 0.6, f"{rt_key}: no native PQC, installable library (kyber-py / dilithium-py / @noble/post-quantum)"
    if rt_key == "c":
        return 1.0, "C/embedded: needs liboqs or OpenSSL >= 3.5 linked in"
    if asset.asset_type in ("certificate", "protocol"):
        return 0.3, "PKI/TLS stack: PQC availability depends on the server software version"
    return 0.7, "runtime unknown"


def score(asset: CryptoAsset, all_assets: list[CryptoAsset] | None = None, runtimes: dict | None = None,
          kb: KnowledgeBase | None = None) -> AgilityScore:
    props = asset.props or {}
    ctx = asset.context or {}
    api = str(props.get("api") or "")
    snippets = " ".join((e.snippet or "") for e in asset.evidence)
    dims: dict[str, float] = {}
    reasons: list[str] = []

    # 1. algorithm coupling: is the algorithm named in code?
    literal = props.get("literal", True)
    if asset.asset_type in ("certificate", "related-crypto-material"):
        dims["algorithm_coupling"] = 0.3
        reasons.append("algorithm is a property of key material; rotation swaps it")
    elif api == "config":
        dims["algorithm_coupling"] = 0.2
        reasons.append("algorithm chosen in configuration, not code")
    elif literal is False:
        dims["algorithm_coupling"] = 0.3
        reasons.append("algorithm name comes from a variable/config value")
    else:
        dims["algorithm_coupling"] = 1.0
        reasons.append("algorithm hardcoded at the call site")

    # 2. provider coupling
    if api == "config" or asset.asset_type in ("protocol",):
        dims["provider_coupling"] = 0.2
        reasons.append("provider is the TLS/SSH stack; swapped by configuration")
    elif asset.asset_type in ("certificate", "related-crypto-material"):
        dims["provider_coupling"] = 0.3
    elif LOW_LEVEL_API.search(api) or LOW_LEVEL_API.search(snippets):
        dims["provider_coupling"] = 1.0
        reasons.append("direct low-level crypto API")
    elif WRAPPER_API.search(api) or WRAPPER_API.search(snippets):
        dims["provider_coupling"] = 0.5
        reasons.append("used through a framework wrapper")
    else:
        dims["provider_coupling"] = 0.7

    # 3. parameter coupling
    if props.get("key_size") and asset.asset_type == "algorithm" and api != "config":
        dims["parameter_coupling"] = 1.0
        reasons.append(f"key size {props.get('key_size')} is a literal")
    elif asset.asset_type == "algorithm" and api != "config":
        dims["parameter_coupling"] = 0.4
    else:
        dims["parameter_coupling"] = 0.2

    # 4. decoupling mechanism
    if api == "config" or asset.asset_type == "protocol" or props.get("configurable"):
        dims["decoupling"] = 0.0
        reasons.append("externalised in a config file")
    elif asset.asset_type in ("certificate", "related-crypto-material"):
        dims["decoupling"] = 0.2
    elif re.search(r"(os\.environ|getenv|settings\.|config\.|\.env|properties)", snippets, re.I):
        dims["decoupling"] = 0.3
        reasons.append("call site reads configuration")
    else:
        dims["decoupling"] = 1.0

    # 5. spread
    sites = {(e.location, e.line) for e in asset.evidence}
    files = {e.location for e in asset.evidence}
    dims["spread"] = min(1.0, 0.5 * min(1.0, len(sites) / 10.0) + 0.5 * min(1.0, len(files) / 5.0))
    reasons.append(f"{len(sites)} call site(s) across {len(files)} file(s)")

    # 6. ownership
    collectors = {e.collector for e in asset.evidence}
    if collectors and collectors <= {"binary", "theia"} or ctx.get("best_effort"):
        dims["ownership"] = 1.0
        reasons.append("only seen in a binary: you may not own the code")
    elif collectors and collectors <= {"container"}:
        dims["ownership"] = 0.9
        reasons.append("only seen inside a container image")
    elif ctx.get("is_vendored") or ctx.get("from_library_only") or asset.provided_by:
        dims["ownership"] = 0.6
        reasons.append("vendored / third-party dependency")
    else:
        dims["ownership"] = 0.2

    # 7. runtime PQC availability
    dims["runtime_pqc"], rt_reason = _runtime_pqc(asset, runtimes, kb)
    reasons.append(rt_reason)

    weighted = sum(WEIGHTS[k] * dims[k] for k in WEIGHTS)
    total = int(round(100 * (1 - weighted)))
    total = max(0, min(100, total))

    if asset.asset_type in ("certificate", "protocol") or api == "config":
        y = 0.5
    else:
        y = 1.0 + 4.0 * (1 - total / 100.0)
    if collectors and collectors <= {"binary", "theia"}:
        y = min(10.0, y * 2)
    if asset.asset_type == "related-crypto-material":
        y = 1.0
    ag = AgilityScore(dimensions={k: round(v, 2) for k, v in dims.items()}, total=total, y_years=round(y, 2), reasons=reasons)
    asset.agility = ag
    return ag


def apply(assets: list[CryptoAsset], runtimes_by_component: dict | None = None, kb: KnowledgeBase | None = None) -> None:
    for a in assets:
        rts = (runtimes_by_component or {}).get(a.component) or (runtimes_by_component or {}).get("*")
        score(a, assets, rts, kb)
