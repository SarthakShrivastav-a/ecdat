"""Certificate & key collector: X.509 (PEM/DER), PKCS#12, Java keystores, PEM private keys.
The fields CERT-In Table 9 asks for are literally in the file, so confidence is high.
cbomkit-theia (optional) adds secrets/keys it recognises."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519
from cryptography.hazmat.primitives.serialization import pkcs12

from ecdat import tools
from ecdat.collectors.base import Collector, Target, path_context, rel, walk_files
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

CERT_EXTS = {".pem", ".crt", ".cer", ".der", ".cert", ".ca-bundle", ".p7b", ".pub"}
KEY_EXTS = {".key", ".pem", ".p8", ".pk8"}
P12_EXTS = {".p12", ".pfx"}
JKS_EXTS = {".jks", ".keystore", ".truststore", ".bks"}
ALL_EXTS = CERT_EXTS | KEY_EXTS | P12_EXTS | JKS_EXTS
PEM_CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
PEM_KEY_RE = re.compile(rb"-----BEGIN (?:(RSA|EC|DSA|ENCRYPTED|OPENSSH) )?PRIVATE KEY-----", re.S)


def _pub_info(pub, kb: KnowledgeBase) -> dict:
    if isinstance(pub, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "key_size": pub.key_size}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return {"algorithm": "ECDSA", "key_size": pub.curve.key_size, "curve": pub.curve.name}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "key_size": 256, "curve": "ed25519"}
    if isinstance(pub, ed448.Ed448PublicKey):
        return {"algorithm": "Ed25519", "key_size": 448, "curve": "ed448"}
    if isinstance(pub, x25519.X25519PublicKey):
        return {"algorithm": "X25519", "key_size": 256, "curve": "curve25519"}
    if isinstance(pub, x448.X448PublicKey):
        return {"algorithm": "X25519", "key_size": 448, "curve": "curve448"}
    if isinstance(pub, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "key_size": pub.key_size}
    name = type(pub).__name__.replace("PublicKey", "")
    return {"algorithm": kb.canonicalise(name) or name, "key_size": getattr(pub, "key_size", None)}


def parse_x509(der_or_pem: bytes, kb: KnowledgeBase) -> dict:
    cert = x509.load_pem_x509_certificate(der_or_pem) if der_or_pem.strip().startswith(b"-----") else x509.load_der_x509_certificate(der_or_pem)
    pub = _pub_info(cert.public_key(), kb)
    sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_name = cert.signature_algorithm_oid._name
    sig_alg = kb.canonicalise(sig_name) or kb.canonicalise(sig_name.split("With")[-1]) or sig_name
    hash_alg = kb.canonicalise(cert.signature_hash_algorithm.name) if cert.signature_hash_algorithm else None
    try:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        nb, na = cert.not_valid_before.replace(tzinfo=timezone.utc), cert.not_valid_after.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    san = []
    try:
        san = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        pass
    is_ca = False
    try:
        is_ca = bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        pass
    cn = None
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        pass
    key_usage = []
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        for attr in ("digital_signature", "key_encipherment", "key_agreement", "key_cert_sign", "data_encipherment"):
            if getattr(ku, attr, False):
                key_usage.append(attr)
    except (x509.ExtensionNotFound, ValueError):
        pass
    return {
        "subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "cn": cn,
        "serial": format(cert.serial_number, "x"), "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "expired": na < now, "days_left": (na - now).days, "self_signed": cert.subject == cert.issuer, "is_ca": is_ca,
        "san": san, "key_usage": key_usage,
        "signature_algorithm": sig_alg, "signature_algorithm_oid": sig_oid, "signature_hash": hash_alg,
        "public_key_algorithm": pub["algorithm"], "key_size": pub.get("key_size"), "curve": pub.get("curve"),
        "public_key_oid": kb.info(pub["algorithm"]).get("oid"),
        "sha256_fingerprint": hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
        "format": "X.509", "version": cert.version.name,
    }


class CertificateCollector(Collector):
    name = "certificate"
    kinds = {"certs", "dir", "repo", "image"}

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        root = Path(target.path)
        passwords = list(target.props.get("passwords") or ["", "changeit", "password", "zoo", "zoopass", "secret"])
        out: list[RawFinding] = []
        for path in walk_files(root, exts=ALL_EXTS):
            location = rel(path, root) if root.is_dir() else path.name
            if target.props.get("location_prefix"):
                location = target.props["location_prefix"] + location
            ctx = path_context(location)
            ctx["zone"] = target.zone
            try:
                data = path.read_bytes()
            except OSError:
                continue
            ext = path.suffix.lower()
            if ext in P12_EXTS:
                out += self._pkcs12(data, location, target, kb, passwords, ctx)
            elif ext in JKS_EXTS:
                out += self._jks(path, location, target, kb, passwords, ctx)
            else:
                out += self._pem_or_der(data, location, path, target, kb, passwords, ctx)
        if target.props.get("use_theia", True) and tools.find("cbomkit-theia") and root.is_dir():
            out += self._theia(root, target, kb)
        return out

    # ---- X.509 / PEM ------------------------------------------------------------------------------
    def _cert_findings(self, info: dict, location: str, target: Target, kb: KnowledgeBase, ctx: dict, ext: str,
                       line: int | None = None, collector: str = "certificate") -> list[RawFinding]:
        name = info.get("cn") or info["subject"]
        props = dict(info)
        props["extension"] = ext
        out = [RawFinding(collector, "certificate", name, location, line, f"CN={info.get('cn')} issuer={info['issuer'][:60]}",
                          "high", target.name, props, dict(ctx))]
        # the public-key algorithm and the signature algorithm are assets in their own right
        out.append(RawFinding(collector, "algorithm", info["public_key_algorithm"], location, line,
                              f"certificate public key {info['public_key_algorithm']}-{info.get('key_size')}", "high", target.name,
                              {"key_size": info.get("key_size"), "curve": info.get("curve"), "api": "x509-public-key",
                               "primitive": "signature" if info["public_key_algorithm"] in ("ECDSA", "Ed25519", "DSA") else "pke",
                               "function": "verify", "certificate": info["sha256_fingerprint"]}, dict(ctx)))
        if info.get("signature_hash"):
            out.append(RawFinding(collector, "algorithm", info["signature_hash"], location, line,
                                  f"certificate signature {info['signature_algorithm_oid']}", "high", target.name,
                                  {"api": "x509-signature", "primitive": "hash", "certificate": info["sha256_fingerprint"]}, dict(ctx)))
        return out

    def _pem_or_der(self, data: bytes, location: str, path: Path, target: Target, kb: KnowledgeBase,
                    passwords: list[str], ctx: dict) -> list[RawFinding]:
        out: list[RawFinding] = []
        certs = PEM_CERT_RE.findall(data)
        if certs:
            for i, blob in enumerate(certs):
                try:
                    info = parse_x509(blob, kb)
                except Exception:
                    continue
                line = data[:data.find(blob)].count(b"\n") + 1
                out += self._cert_findings(info, location, target, kb, ctx, path.suffix.lower(), line)
        elif path.suffix.lower() in CERT_EXTS and not data.strip().startswith(b"-----"):
            try:
                info = parse_x509(data, kb)
                out += self._cert_findings(info, location, target, kb, ctx, path.suffix.lower())
            except Exception:
                pass
        m = PEM_KEY_RE.search(data)
        if m:
            out += self._private_key(data, location, path, target, kb, passwords, ctx)
        elif path.suffix.lower() in {".key", ".p8", ".pk8"} and not certs:
            out += self._private_key(data, location, path, target, kb, passwords, ctx, der=True)
        if b"ssh-rsa " in data or b"ssh-ed25519 " in data or b"ecdsa-sha2-nistp" in data:
            for mm in re.finditer(rb"(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d{3}|ssh-dss)\s+[A-Za-z0-9+/=]+", data):
                alg = kb.canonicalise(mm.group(1).decode())
                if alg:
                    out.append(RawFinding("certificate", "related-crypto-material", f"ssh-public-key:{alg}", location,
                                          data[:mm.start()].count(b"\n") + 1, mm.group(1).decode(), "high", target.name,
                                          {"type": "public-key", "algorithm": alg, "format": "OpenSSH"}, dict(ctx)))
        return out

    def _private_key(self, data: bytes, location: str, path: Path, target: Target, kb: KnowledgeBase, passwords: list[str],
                     ctx: dict, der: bool = False) -> list[RawFinding]:
        key = None
        encrypted = b"ENCRYPTED" in data or b"Proc-Type: 4,ENCRYPTED" in data
        for pw in ([None] + [p.encode() for p in passwords if p]):
            try:
                if der:
                    key = serialization.load_der_private_key(data, password=pw)
                elif b"OPENSSH PRIVATE KEY" in data:
                    key = serialization.load_ssh_private_key(data, password=pw)
                else:
                    key = serialization.load_pem_private_key(data, password=pw)
                break
            except Exception:
                continue
        if key is None:
            m = re.search(rb"BEGIN (RSA|EC|DSA) PRIVATE KEY", data)
            alg = kb.canonicalise(m.group(1).decode()) if m else None
            return [RawFinding("certificate", "related-crypto-material", f"private-key:{alg or 'unknown'}", location, 1,
                               "private key (could not decrypt)", "medium", target.name,
                               {"type": "private-key", "algorithm": alg, "encrypted": encrypted, "format": "PEM", "locked": True}, dict(ctx))]
        info = _pub_info(key.public_key(), kb)
        return [RawFinding("certificate", "related-crypto-material", f"private-key:{info['algorithm']}", location, 1,
                           f"{info['algorithm']} private key {info.get('key_size')}-bit", "high", target.name,
                           {"type": "private-key", "algorithm": info["algorithm"], "key_size": info.get("key_size"),
                            "curve": info.get("curve"), "encrypted": encrypted, "format": "DER" if der else "PEM",
                            "state": "active"}, dict(ctx)),
                RawFinding("certificate", "algorithm", info["algorithm"], location, 1, "private key material", "high", target.name,
                           {"key_size": info.get("key_size"), "curve": info.get("curve"), "api": "private-key",
                            "primitive": "signature" if info["algorithm"] in ("ECDSA", "Ed25519", "DSA") else "pke"}, dict(ctx))]

    # ---- PKCS#12 ---------------------------------------------------------------------------------
    def _pkcs12(self, data: bytes, location: str, target: Target, kb: KnowledgeBase, passwords: list[str], ctx: dict):
        for pw in ([None] + [p.encode() for p in passwords]):
            try:
                key, cert, chain = pkcs12.load_key_and_certificates(data, pw)
            except Exception:
                continue
            out = []
            if cert is not None:
                out += self._cert_findings(parse_x509(cert.public_bytes(serialization.Encoding.DER), kb), location, target, kb, ctx, ".p12")
            for c in chain or []:
                out += self._cert_findings(parse_x509(c.public_bytes(serialization.Encoding.DER), kb), location, target, kb, ctx, ".p12")
            if key is not None:
                info = _pub_info(key.public_key(), kb)
                out.append(RawFinding("certificate", "related-crypto-material", f"private-key:{info['algorithm']}", location, None,
                                      "PKCS#12 private key", "high", target.name,
                                      {"type": "private-key", "algorithm": info["algorithm"], "key_size": info.get("key_size"),
                                       "curve": info.get("curve"), "format": "PKCS#12", "state": "active",
                                       "password_protected": bool(pw)}, dict(ctx)))
            return out
        return [RawFinding("certificate", "related-crypto-material", "pkcs12-keystore", location, None, "PKCS#12 (locked)",
                           "low", target.name, {"type": "keystore", "format": "PKCS#12", "locked": True}, dict(ctx))]

    # ---- Java keystore ---------------------------------------------------------------------------
    def _jks(self, path: Path, location: str, target: Target, kb: KnowledgeBase, passwords: list[str], ctx: dict):
        try:
            import jks
        except ImportError:
            return []
        for pw in passwords:
            try:
                ks = jks.KeyStore.load(str(path), pw)
            except Exception:
                continue
            if ks.store_type == "pkcs12" or not (ks.private_keys or ks.certs):
                break
            out = []
            for alias, pk in ks.private_keys.items():
                try:
                    if not pk.is_decrypted():
                        pk.decrypt(pw)
                except Exception:
                    pass
                info = {"algorithm": None, "key_size": None}
                try:
                    key = serialization.load_der_private_key(pk.pkey_pkcs8, None)
                    info = _pub_info(key.public_key(), kb)
                except Exception:
                    info["algorithm"] = kb.canonicalise(pk.algorithm_oid and ".".join(map(str, pk.algorithm_oid)) or "") or "unknown"
                out.append(RawFinding("certificate", "related-crypto-material", f"private-key:{info['algorithm']}", location, None,
                                      f"JKS alias '{alias}'", "high", target.name,
                                      {"type": "private-key", "algorithm": info["algorithm"], "key_size": info.get("key_size"),
                                       "curve": info.get("curve"), "format": "JKS", "alias": alias, "state": "active",
                                       "password_protected": True}, dict(ctx)))
                if info.get("algorithm") and info["algorithm"] != "unknown":
                    out.append(RawFinding("certificate", "algorithm", info["algorithm"], location, None, f"JKS key '{alias}'", "high",
                                          target.name, {"key_size": info.get("key_size"), "api": "jks-private-key",
                                                        "primitive": "signature" if info["algorithm"] in ("ECDSA", "Ed25519", "DSA") else "pke"}, dict(ctx)))
                for c in pk.cert_chain:
                    try:
                        out += self._cert_findings(parse_x509(c[1], kb), location, target, kb, ctx, ".jks")
                    except Exception:
                        pass
            for alias, c in ks.certs.items():
                try:
                    out += self._cert_findings(parse_x509(c.cert, kb), location, target, kb, ctx, ".jks")
                except Exception:
                    pass
            return out
        # keytool >= JDK 9 writes PKCS#12 even for *.jks names: fall back to the PKCS#12 parser
        try:
            data = path.read_bytes()
        except OSError:
            data = b""
        out = self._pkcs12(data, location, target, kb, passwords, ctx) if data else []
        if out and not (len(out) == 1 and out[0].props.get("locked")):
            for f in out:
                f.props["format"] = "PKCS#12 (.jks)"
            return out
        return [RawFinding("certificate", "related-crypto-material", "java-keystore", location, None, "JKS (locked)", "low",
                           target.name, {"type": "keystore", "format": "JKS", "locked": True}, dict(ctx))]

    # ---- cbomkit-theia (optional) ----------------------------------------------------------------
    def _theia(self, root: Path, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        exe = tools.find("cbomkit-theia")
        try:
            proc = subprocess.run([str(exe), "dir", str(root), "--log-level", "error"], capture_output=True, text=True,
                                  timeout=300, encoding="utf-8", errors="replace")
            data = json.loads(proc.stdout[proc.stdout.find("{"):])
        except Exception:
            return []
        out = []
        for c in (data.get("components") or []):
            cp = c.get("cryptoProperties") or {}
            at = cp.get("assetType")
            if not at:
                continue
            occ = ((c.get("evidence") or {}).get("occurrences") or [{}])[0]
            location = occ.get("location", "?")
            if target.props.get("location_prefix"):
                location = target.props["location_prefix"] + location
            ctx = path_context(location)
            ctx["zone"] = target.zone
            name = c.get("name", "?")
            props = {"api": "theia", "theia_type": at, "description": c.get("description"), "oid": cp.get("oid")}
            if at == "related-crypto-material":
                rp = cp.get("relatedCryptoMaterialProperties", {})
                props.update({"type": rp.get("type"), "key_size": rp.get("size"), "format": rp.get("format")})
                alg = kb.canonicalise(re.split(r"[-_ ]", name)[0]) if name else None
                if alg:
                    props["algorithm"] = alg
                out.append(RawFinding("theia", "related-crypto-material", f"{rp.get('type', 'material')}:{alg or name}", location,
                                      occ.get("line") or None, name, "medium", target.name, props, ctx))
            elif at == "algorithm":
                alg = kb.canonicalise(name)
                if alg:
                    out.append(RawFinding("theia", "algorithm", alg, location, occ.get("line") or None, name, "medium", target.name, props, ctx))
            elif at == "certificate":
                cert = cp.get("certificateProperties", {})
                props.update({"subject": cert.get("subjectName"), "issuer": cert.get("issuerName"),
                              "not_after": cert.get("notValidAfter"), "not_before": cert.get("notValidBefore")})
                out.append(RawFinding("theia", "certificate", name, location, None, name, "medium", target.name, props, ctx))
            elif at == "protocol":
                pp = cp.get("protocolProperties", {})
                props.update({"type": pp.get("type"), "versions": [pp.get("version")] if pp.get("version") else [],
                              "cipher_suites": [s.get("name") for s in pp.get("cipherSuites", [])]})
                out.append(RawFinding("theia", "protocol", (pp.get("type") or "TLS").upper(), location, None, name, "medium", target.name, props, ctx))
        return out
