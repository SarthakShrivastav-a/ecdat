"""CycloneDX 1.7 CBOM emission + validation against the vendored schema.
We build the JSON directly (the schema is the contract), validate with jsonschema, and keep ecdat analytics in
component `properties` (namespace ecdat:*) so the file stays a valid, tool-agnostic CBOM."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ecdat import __version__, tools
from ecdat.model import CryptoAsset, ScanResult

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"
SPEC_VERSION = "1.7"
_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree", "kem", "ae",
               "combiner", "key-wrap", "other", "unknown"}
_FUNCS = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive", "sign", "verify", "encapsulate", "decapsulate",
          "other", "unknown"}
_FUNC_MAP = {"derive": "keyderive", "keyagree": "other", "encapsulate": "encapsulate", "decapsulate": "decapsulate"}
_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
_PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"}
_PROTO_TYPES = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}
_MATERIAL_TYPES = {"private-key", "public-key", "secret-key", "key", "ciphertext", "signature", "digest", "initialization-vector",
                   "nonce", "seed", "salt", "shared-secret", "tag", "additional-data", "password", "credential", "token", "other", "unknown"}


def _prop(name: str, value) -> dict | None:
    if value is None or value == "" or value == [] or value == {}:
        return None
    if isinstance(value, (dict, list)):
        value = json.dumps(value, default=str)
    return {"name": name, "value": str(value)}


def _props(pairs: dict) -> list[dict]:
    return [p for p in (_prop(k, v) for k, v in pairs.items()) if p]


def _ts(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


_FAMILIES: set[str] = set()


def registry_families() -> set[str]:
    global _FAMILIES
    if not _FAMILIES:
        defs = json.loads((SCHEMAS / "cryptography-defs.json").read_text(encoding="utf-8"))
        _FAMILIES = {x["family"] for x in defs["algorithms"]}
    return _FAMILIES


def _algorithm_properties(a: CryptoAsset) -> dict:
    ap: dict = {"primitive": a.primitive if a.primitive in _PRIMITIVES else "unknown"}
    if a.family and a.family in registry_families():
        ap["algorithmFamily"] = a.family
    if a.parameter_set:
        ap["parameterSetIdentifier"] = a.parameter_set
    elif a.key_size:
        ap["parameterSetIdentifier"] = str(a.key_size)
    if a.curve:
        ap["curve"] = a.curve
    if a.mode and a.mode.lower() in _MODES:
        ap["mode"] = a.mode.lower()
    if a.padding:
        pl = a.padding.lower().replace("padding", "").replace("-", "")
        ap["padding"] = pl if pl in _PADDINGS else "other"
    funcs = [(_FUNC_MAP.get(f, f)) for f in a.crypto_functions]
    funcs = [f for f in funcs if f in _FUNCS]
    if funcs:
        ap["cryptoFunctions"] = sorted(set(funcs))
    if a.classical_security_level is not None:
        ap["classicalSecurityLevel"] = int(a.classical_security_level)
    if a.nist_quantum_security_level is not None:
        ap["nistQuantumSecurityLevel"] = int(a.nist_quantum_security_level)
    ap["executionEnvironment"] = "software-plain-ram"
    return ap


def _certificate_properties(a: CryptoAsset) -> dict:
    p = a.props
    cp = {"subjectName": p.get("subject"), "issuerName": p.get("issuer"), "notValidBefore": _ts(p.get("not_before")),
          "notValidAfter": _ts(p.get("not_after")), "certificateFormat": p.get("format", "X.509"),
          "certificateExtension": (p.get("extension") or ".crt").lstrip("."), "serialNumber": p.get("serial"),
          "certificateState": [{"state": "revoked" if p.get("revoked") else ("deactivated" if p.get("expired") else "active")}]}
    if p.get("sha256_fingerprint"):
        cp["fingerprint"] = {"alg": "SHA-256", "content": p["sha256_fingerprint"]}
    if p.get("signature_algorithm_ref"):
        cp["signatureAlgorithmRef"] = p["signature_algorithm_ref"]
    if p.get("subject_public_key_ref"):
        cp["subjectPublicKeyRef"] = p["subject_public_key_ref"]
    return {k: v for k, v in cp.items() if v not in (None, "")}


def _protocol_properties(a: CryptoAsset) -> dict:
    p = a.props
    t = (p.get("type") or a.name or "unknown").lower()
    pp: dict = {"type": t if t in _PROTO_TYPES else "other"}
    vers = p.get("versions") or []
    if vers:
        pp["version"] = ", ".join(vers)
    suites = p.get("cipher_suites") or []
    if suites:
        pp["cipherSuites"] = [{"name": s} for s in suites[:64]]
    return pp


def _material_properties(a: CryptoAsset) -> dict:
    p = a.props
    t = (p.get("type") or "unknown").lower()
    mp: dict = {"type": t if t in _MATERIAL_TYPES else "other"}
    if a.key_size or p.get("key_size"):
        mp["size"] = int(a.key_size or p.get("key_size"))
    if p.get("state"):
        mp["state"] = p["state"] if p["state"] in ("pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed") else "active"
    if p.get("format"):
        mp["format"] = p["format"]
    if p.get("alias") or p.get("id"):
        mp["id"] = str(p.get("alias") or p.get("id"))
    if p.get("algorithm_ref"):
        mp["algorithmRef"] = p["algorithm_ref"]
    return mp


def asset_component(a: CryptoAsset) -> dict:
    cp: dict = {"assetType": a.asset_type}
    if a.oid:
        cp["oid"] = a.oid
    if a.asset_type == "algorithm":
        cp["algorithmProperties"] = _algorithm_properties(a)
    elif a.asset_type == "certificate":
        cp["certificateProperties"] = _certificate_properties(a)
    elif a.asset_type == "protocol":
        cp["protocolProperties"] = _protocol_properties(a)
    else:
        cp["relatedCryptoMaterialProperties"] = _material_properties(a)
    occurrences = []
    for e in a.evidence[:50]:
        occ = {"location": e.location}
        if e.line:
            occ["line"] = int(e.line)
        occurrences.append(occ)
    name = a.name
    if a.asset_type == "algorithm" and a.key_size and not name.endswith(str(a.key_size)):
        name = f"{a.name}-{a.key_size}"
    if a.asset_type == "algorithm" and a.mode:
        name = f"{name}-{a.mode.upper()}"
    comp = {"type": "cryptographic-asset", "bom-ref": a.bom_ref, "name": name, "cryptoProperties": cp}
    if occurrences:
        comp["evidence"] = {"occurrences": occurrences}
    risk = a.risk.to_dict() if a.risk else {}
    agility = a.agility.to_dict() if a.agility else {}
    rec = a.recommendation.to_dict() if a.recommendation else {}
    comp["properties"] = _props({
        "ecdat:component": a.component, "ecdat:confidence": a.confidence, "ecdat:collectors": ",".join(a.context.get("collectors", [])),
        "ecdat:corroborated": str(a.context.get("corroborated", False)).lower(), "ecdat:usage": a.context.get("usage"),
        "ecdat:best_effort": "true" if a.context.get("best_effort") else None,
        "ecdat:exposure": a.exposure.get("zone") if a.exposure else None,
        "ecdat:lifetime_years": a.lifetime_years, "ecdat:data_class": a.data_class, "ecdat:criticality": a.criticality,
        "ecdat:agility": agility.get("total"), "ecdat:migration_years": agility.get("y_years"),
        "ecdat:quantum_class": risk.get("quantum_class"), "ecdat:hndl_applicable": str(risk.get("hndl_applicable")).lower() if risk else None,
        "ecdat:tier": risk.get("tier"), "ecdat:priority": risk.get("priority"), "ecdat:mosca_gap_years": risk.get("mosca_gap"),
        "ecdat:recommendation": rec.get("target"), "ecdat:effort_weeks": rec.get("effort_weeks"), "ecdat:vex": a.vex,
        "ecdat:certin_completeness_pct": (a.certin or {}).get("pct"),
    })
    return comp


def to_bom(result: ScanResult, include_vex: bool = True) -> dict:
    versions = result.tool_versions or tools.versions()
    tool_components = [{"type": "application", "name": "ecdat", "version": __version__,
                        "description": "Enterprise Cryptographic Discovery & Analysis Tool (SIH 2026 PS 26164)"}]
    for n in ("opengrep", "cbomkit-theia", "syft", "tshark", "crane"):
        if versions.get(n):
            tool_components.append({"type": "application", "name": n, "version": str(versions[n])[:60]})
    root_ref = f"urn:ecdat:scan:{result.id or uuid.uuid4().hex[:12]}"
    comps = [c if isinstance(c, dict) else c.to_dict() for c in result.components]
    components: list[dict] = []
    deps: dict[str, dict] = {root_ref: {"ref": root_ref, "dependsOn": []}}
    app_ref = {d["name"]: d["bom_ref"] for d in comps if d.get("type") != "library"}
    for d in comps:
        ctype = d.get("type") if d.get("type") in ("application", "library", "container", "file", "device") else "application"
        comp = {"type": ctype, "bom-ref": d["bom_ref"], "name": d["name"]}
        if d.get("version"):
            comp["version"] = str(d["version"])
        p = d.get("props") or {}
        comp["properties"] = _props({"ecdat:zone": d.get("zone"), "ecdat:data_class": d.get("data_class"),
                                     "ecdat:criticality": d.get("criticality"), "ecdat:path": d.get("path"),
                                     "ecdat:ecosystem": p.get("ecosystem"),
                                     "ecdat:pqc_native": str(p.get("pqc_native")).lower() if p.get("pqc_native") is not None else None,
                                     "ecdat:pqc_native_from": p.get("pqc_native_from")})
        components.append(comp)
        deps.setdefault(d["bom_ref"], {"ref": d["bom_ref"], "dependsOn": []})
        if ctype == "library":
            owner_ref = app_ref.get(p.get("component"))
            if owner_ref:
                deps.setdefault(owner_ref, {"ref": owner_ref, "dependsOn": []})
                if d["bom_ref"] not in deps[owner_ref]["dependsOn"]:
                    deps[owner_ref]["dependsOn"].append(d["bom_ref"])
            provides = p.get("provides_refs") or []
            if provides:
                deps[d["bom_ref"]]["provides"] = list(dict.fromkeys(provides))
        else:
            deps[root_ref]["dependsOn"].append(d["bom_ref"])
    comp_ref = app_ref
    for a in result.assets:
        components.append(asset_component(a))
        owner = comp_ref.get(a.component)
        if owner:
            deps.setdefault(owner, {"ref": owner, "dependsOn": []})
            if a.provided_by:
                deps.setdefault(a.provided_by, {"ref": a.provided_by, "dependsOn": []})
                deps[a.provided_by].setdefault("provides", [])
                if a.bom_ref not in deps[a.provided_by]["provides"]:
                    deps[a.provided_by]["provides"].append(a.bom_ref)
            else:
                deps[owner]["dependsOn"].append(a.bom_ref)
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     "tools": {"components": tool_components},
                     "component": {"type": "application", "bom-ref": root_ref, "name": result.name or "ecdat-scan"},
                     "properties": _props({"ecdat:z_year": result.params.z_year, "ecdat:profile": result.params.profile,
                                           "ecdat:targets": len(result.targets), "ecdat:certin_table9": "CERT-In BOM guidelines v2.0 (2025-07-09) section 8.3",
                                           "ecdat:stats": result.stats.get("per_collector")})},
        "components": components,
        "dependencies": [{k: v for k, v in d.items() if k != "dependsOn" or v} for d in deps.values()],
    }
    if include_vex and result.plan.get("vex"):
        bom["vulnerabilities"] = result.plan["vex"]
    return bom


_validator = None


def validator():
    global _validator
    if _validator is None:
        import jsonschema
        from referencing import Registry, Resource
        main = json.loads((SCHEMAS / "bom-1.7.schema.json").read_text(encoding="utf-8"))
        spdx = json.loads((SCHEMAS / "spdx.schema.json").read_text(encoding="utf-8"))
        jsf = json.loads((SCHEMAS / "jsf-0.82.schema.json").read_text(encoding="utf-8"))
        cdefs = json.loads((SCHEMAS / "cryptography-defs.schema.json").read_text(encoding="utf-8"))
        reg = Registry().with_resources([
            ("cryptography-defs.schema.json", Resource.from_contents(cdefs)),
            ("http://cyclonedx.org/schema/cryptography-defs.schema.json", Resource.from_contents(cdefs)),
            ("https://cyclonedx.org/schema/cryptography-defs.schema.json", Resource.from_contents(cdefs)),
            ("spdx.schema.json", Resource.from_contents(spdx)), ("jsf-0.82.schema.json", Resource.from_contents(jsf)),
            ("http://cyclonedx.org/schema/spdx.schema.json", Resource.from_contents(spdx)),
            ("http://cyclonedx.org/schema/jsf-0.82.schema.json", Resource.from_contents(jsf)),
            ("http://cyclonedx.org/schema/bom-1.7.schema.json", Resource.from_contents(main)),
        ])
        _validator = jsonschema.Draft7Validator(main, registry=reg)
    return _validator


def validate(bom: dict) -> list[str]:
    errs = []
    for e in validator().iter_errors(bom):
        path = "/".join(str(p) for p in e.absolute_path)
        errs.append(f"{path}: {e.message[:160]}")
    return errs


def write(bom: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
