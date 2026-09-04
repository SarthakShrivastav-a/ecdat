"""Merge RawFindings into CryptoAssets: one asset per (component, type, canonical name, key size, mode),
all evidence attached, confidence = max, corroboration by >= 2 distinct collectors bumps confidence.
Libraries become Components with `provides` edges; algorithms they provide but nobody uses are emitted as
low-confidence inventory assets flagged from_library_only."""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ecdat.knowledge import KnowledgeBase
from ecdat.model import CONF_ORDER, Component, CryptoAsset, RawFinding, bump

PRIMITIVE_DEFAULT = {"RSA": "pke", "DH": "key-agree", "ECDH": "key-agree", "X25519": "key-agree", "ECDSA": "signature",
                     "Ed25519": "signature", "DSA": "signature"}
PRIMITIVE_ENUM = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree",
                  "kem", "ae", "combiner", "key-wrap", "other", "unknown"}


def _ref(*parts) -> str:
    h = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]
    return f"urn:ecdat:{parts[0]}:{h}"


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-").lower()


def merge(findings: list[RawFinding], targets: list, kb: KnowledgeBase) -> tuple[list[CryptoAsset], list[Component]]:
    components: dict[str, Component] = {}
    for t in targets:
        ctype = {"image": "container", "endpoints": "device", "pcap": "device", "certs": "file", "binary": "application"}.get(t.kind, "application")
        components[t.name] = Component(bom_ref=f"urn:ecdat:component:{_slug(t.name)}", name=t.name, type=ctype, zone=t.zone,
                                       data_class=t.data_class, criticality=t.criticality, path=t.path, props={"kind": t.kind})

    groups: dict[tuple, list[RawFinding]] = defaultdict(list)
    for f in findings:
        if f.asset_type == "algorithm":
            canon = kb.canonicalise(f.name, f.props.get("key_size")) or f.name
            key = ("algorithm", f.component, canon, f.props.get("key_size"), (f.props.get("mode") or "").upper() or None)
        elif f.asset_type == "certificate":
            key = ("certificate", f.component, f.props.get("sha256_fingerprint") or f.name)
        elif f.asset_type == "protocol":
            key = ("protocol", f.component, (f.props.get("type") or f.name).lower(), f.location)
        elif f.asset_type == "library":
            key = ("library", f.component, f.name, f.props.get("version"))
        else:
            key = ("related-crypto-material", f.component, f.name, f.location)
        groups[key].append(f)

    assets: list[CryptoAsset] = []
    lib_components: dict[tuple, Component] = {}
    for key, fs in groups.items():
        kind = key[0]
        fs_sorted = sorted(fs, key=lambda f: (-CONF_ORDER[f.confidence], f.line or 0))
        first = fs_sorted[0]
        collectors = {f.collector for f in fs}
        conf = max((f.confidence for f in fs), key=lambda c: CONF_ORDER[c])
        corroborated = len(collectors) >= 2
        if corroborated:
            conf = bump(conf)
        evidence = [f.evidence() for f in fs_sorted]
        ctx = {"corroborated": corroborated, "collectors": sorted(collectors)}
        for k in ("best_effort", "container", "live", "pcap"):
            if any(f.context.get(k) for f in fs):
                ctx[k] = True
        ctx["is_test"] = all(f.context.get("is_test") for f in fs)
        ctx["in_comment"] = all(f.context.get("in_comment") for f in fs)
        ctx["is_vendored"] = all(f.context.get("is_vendored") for f in fs)
        ctx["regex_only"] = all(f.context.get("regex_fallback") for f in fs)
        comp = components.get(first.component)
        if kind == "library":
            props = dict(first.props)
            for f in fs[1:]:
                for k, v in f.props.items():
                    props.setdefault(k, v)
            lib = Component(bom_ref=_ref("library", first.component, first.name, props.get("version")), name=first.name,
                            type="library", version=props.get("version"), zone=comp.zone if comp else "internal",
                            path=first.location, props={**props, "component": first.component, "evidence": [e.to_dict() for e in evidence],
                                                        "confidence": conf, "collectors": sorted(collectors)})
            lib_components[(first.component, first.name)] = lib
            continue
        if kind == "algorithm":
            canon = key[2]
            info = kb.info(canon)
            merged_props: dict = {}
            for f in fs_sorted:
                for k, v in f.props.items():
                    if v not in (None, "", []) and k not in merged_props:
                        merged_props[k] = v
            primitive = merged_props.get("primitive") or info.get("primitive") or PRIMITIVE_DEFAULT.get(canon, "unknown")
            if primitive not in PRIMITIVE_ENUM:
                primitive = "other"
            key_size = key[3] or info.get("key_size")
            functions = sorted({f.props["function"] for f in fs if f.props.get("function")}) or list(info.get("functions", []))
            curve = merged_props.get("curve")
            cinfo = kb.curve(curve) if curve else None
            a = CryptoAsset(bom_ref=_ref("algorithm", first.component, canon, key_size, key[4]), asset_type="algorithm", name=canon,
                            family=info.get("family", canon), primitive=primitive, key_size=key_size, mode=key[4],
                            padding=merged_props.get("padding"), oid=info.get("oid"), curve=(cinfo or {}).get("name", curve) if curve else None,
                            parameter_set=canon if kb.is_pqc(canon) else None, crypto_functions=functions,
                            classical_security_level=kb.security_bits(canon, key_size), nist_quantum_security_level=info.get("nist_quantum_level"),
                            component=first.component, confidence=conf, evidence=evidence,
                            props={k: v for k, v in merged_props.items() if k not in ("primitive", "key_size", "mode", "padding", "curve")},
                            context=ctx)
            if curve and cinfo:
                a.props["curve_oid"] = cinfo.get("oid")
            assets.append(a)
        elif kind == "certificate":
            p = dict(first.props)
            a = CryptoAsset(bom_ref=_ref("certificate", first.component, key[2]), asset_type="certificate", name=first.name,
                            family="X.509", primitive="other", key_size=p.get("key_size"), oid=p.get("signature_algorithm_oid"),
                            curve=p.get("curve"), component=first.component, confidence=conf, evidence=evidence, props=p, context=ctx)
            assets.append(a)
        elif kind == "protocol":
            p = dict(first.props)
            for f in fs_sorted[1:]:
                for k in ("versions", "cipher_suites", "curves"):
                    if f.props.get(k):
                        p[k] = sorted(set(p.get(k) or []) | set(f.props[k]))
            a = CryptoAsset(bom_ref=_ref("protocol", first.component, key[2], key[3]), asset_type="protocol", name=first.name.upper(),
                            family=first.name.upper(), primitive="other", component=first.component, confidence=conf, evidence=evidence,
                            props=p, context=ctx)
            assets.append(a)
        else:
            p = dict(first.props)
            a = CryptoAsset(bom_ref=_ref("material", first.component, first.name, first.location), asset_type="related-crypto-material",
                            name=first.name, family=p.get("algorithm"), primitive="other", key_size=p.get("key_size"), curve=p.get("curve"),
                            component=first.component, confidence=conf, evidence=evidence, props=p, context=ctx)
            assets.append(a)

    # provides edges + library-only inventory assets
    used = {(a.component, a.name) for a in assets if a.asset_type == "algorithm"}
    for (comp_name, lib_name), lib in lib_components.items():
        provides = lib.props.get("provides") or []
        lib.props["provides_refs"] = []
        for alg in provides:
            canon = kb.canonicalise(alg) or alg
            match = [a for a in assets if a.asset_type == "algorithm" and a.component == comp_name and a.name == canon]
            if match:
                for a in match:
                    if a.provided_by is None or lib.props.get("wrapper") is False:
                        a.provided_by = lib.bom_ref
                    lib.props["provides_refs"].append(a.bom_ref)
            elif not lib.props.get("wrapper") and not lib.props.get("stdlib") and canon in kb.algorithms:
                info = kb.info(canon)
                a = CryptoAsset(bom_ref=_ref("algorithm", comp_name, canon, None, None, "lib", lib_name), asset_type="algorithm", name=canon,
                                family=info.get("family", canon), primitive=info.get("primitive", "unknown"), oid=info.get("oid"),
                                nist_quantum_security_level=info.get("nist_quantum_level"), component=comp_name, provided_by=lib.bom_ref,
                                confidence="low", evidence=[lib.props["evidence"][0].__class__(**lib.props["evidence"][0]) if False else None][:0],
                                props={"api": "library-capability", "library": lib_name},
                                context={"from_library_only": True, "collectors": lib.props.get("collectors", []), "corroborated": False,
                                         "is_test": False, "in_comment": False, "is_vendored": False, "regex_only": False})
                from ecdat.model import Evidence
                a.evidence = [Evidence("dependency", lib.path or lib_name, None, f"{lib_name} provides {canon}", "low", {"from_library_only": True})]
                assets.append(a)
                lib.props["provides_refs"].append(a.bom_ref)
                used.add((comp_name, canon))
    assets = _absorb_duplicates(assets)
    # bom-refs must be unique across the BOM
    seen_refs: dict[str, int] = {}
    for a in assets:
        n = seen_refs.get(a.bom_ref, 0)
        seen_refs[a.bom_ref] = n + 1
        if n:
            a.bom_ref = f"{a.bom_ref}-{n + 1}"
    comps = list(components.values()) + list(lib_components.values())
    return assets, comps


def _absorb(into: CryptoAsset, victim: CryptoAsset) -> None:
    into.evidence.extend(victim.evidence)
    into.context["collectors"] = sorted(set(into.context.get("collectors", [])) | set(victim.context.get("collectors", [])))
    into.context["corroborated"] = len(into.context["collectors"]) >= 2
    if into.context["corroborated"] and CONF_ORDER[into.confidence] < 2:
        into.confidence = bump(into.confidence)
    for k, v in victim.props.items():
        into.props.setdefault(k, v)
    for k in ("best_effort", "container", "live", "pcap"):
        if victim.context.get(k):
            into.context[k] = True
    into.context.setdefault("absorbed", []).append(victim.bom_ref)


def _absorb_duplicates(assets: list[CryptoAsset]) -> list[CryptoAsset]:
    """Same component + same canonical algorithm: an asset with no key size (or no mode) adds no inventory information
    beside a sized/moded sibling -> fold it in as evidence. Certificates without a fingerprint (theia) fold into the
    parsed certificate with the same subject."""
    out: list[CryptoAsset] = []
    algs = [a for a in assets if a.asset_type == "algorithm"]
    by_comp_name: dict[tuple, list[CryptoAsset]] = defaultdict(list)
    for a in algs:
        by_comp_name[(a.component, a.name)].append(a)
    dropped: set[int] = set()
    for group in by_comp_name.values():
        if len(group) < 2:
            continue
        # richest first: has key size, has mode, most evidence
        group.sort(key=lambda a: (a.key_size is not None, a.mode is not None, len(a.evidence)), reverse=True)
        keep: list[CryptoAsset] = []
        for a in group:
            target = None
            for k in keep:
                same_size = a.key_size is None or k.key_size == a.key_size
                same_mode = a.mode is None or k.mode == a.mode or k.mode is None
                if same_size and same_mode and (a.key_size is None or a.mode is None or k.mode is None):
                    target = k
                    break
            if target is not None and (a.key_size is None or a.mode is None or (target.mode is None and a.mode is not None)):
                if target.mode is None and a.mode is not None:
                    target.mode = a.mode
                _absorb(target, a)
                dropped.add(id(a))
            else:
                keep.append(a)
    certs = [a for a in assets if a.asset_type == "certificate"]
    with_fp = {(a.component, a.name): a for a in certs if a.props.get("sha256_fingerprint")}
    for a in certs:
        if not a.props.get("sha256_fingerprint") and (a.component, a.name) in with_fp:
            _absorb(with_fp[(a.component, a.name)], a)
            dropped.add(id(a))
    for a in assets:
        if id(a) not in dropped:
            out.append(a)
    return out
