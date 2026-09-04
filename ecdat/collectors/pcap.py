"""Pcap collector: reconstruct TLS handshakes (ClientHello/ServerHello/Certificate) from packet captures with scapy,
including STARTTLS upgrades on SMTP/IMAP/POP3. tshark (optional) cross-checks negotiated suites."""
from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from ecdat import tools
from ecdat.collectors.base import Collector, Target
from ecdat.collectors.certificate import parse_x509
from ecdat.collectors.source import suite_algorithms
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
APP_PORTS = {25: "smtp", 587: "smtp", 465: "smtps", 143: "imap", 993: "imaps", 110: "pop3", 995: "pop3s", 443: "https",
             8443: "https", 22: "ssh", 636: "ldaps", 389: "ldap", 5432: "postgres", 3306: "mysql", 1433: "mssql"}
GROUP_NAMES = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072",
               0x11ec: "X25519MLKEM768", 0x11eb: "SecP256r1MLKEM768", 0x6399: "X25519Kyber768Draft00"}


def _suite_name(code: int) -> str:
    try:
        from scapy.layers.tls.crypto.suites import _tls_cipher_suites
        return _tls_cipher_suites.get(code, f"0x{code:04x}")
    except Exception:
        return f"0x{code:04x}"


def _ext_versions(hello) -> list[str]:
    vers = []
    for e in getattr(hello, "ext", None) or []:
        if e.__class__.__name__.startswith("TLS_Ext_SupportedVersion"):
            for v in getattr(e, "versions", None) or [getattr(e, "version", None)]:
                if v in VERSIONS:
                    vers.append(VERSIONS[v])
    return vers


def _ext_groups(hello) -> list[str]:
    for e in getattr(hello, "ext", None) or []:
        if e.__class__.__name__ == "TLS_Ext_SupportedGroups":
            return [GROUP_NAMES.get(g, str(g)) for g in (getattr(e, "groups", None) or [])]
    return []


def _ext_keyshare_group(hello) -> str | None:
    for e in getattr(hello, "ext", None) or []:
        if e.__class__.__name__.startswith("TLS_Ext_KeyShare"):
            ks = getattr(e, "server_share", None)
            if ks is not None and getattr(ks, "group", None) is not None:
                return GROUP_NAMES.get(ks.group, str(ks.group))
    return None


def _sni(hello) -> str | None:
    for e in getattr(hello, "ext", None) or []:
        if e.__class__.__name__ == "TLS_Ext_ServerName":
            names = getattr(e, "servernames", None) or []
            if names:
                n = getattr(names[0], "servername", None)
                return n.decode("ascii", "replace") if isinstance(n, bytes) else n
    return None


class PcapCollector(Collector):
    name = "pcap"
    kinds = {"pcap"}

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        from scapy.all import IP, IPv6, TCP, Raw, load_layer, rdpcap
        load_layer("tls")
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSCertificate

        path = Path(target.path)
        pkts = rdpcap(str(path))
        sessions: dict[tuple, dict] = {}
        order: list[tuple] = []

        def key_of(pkt):
            ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None or TCP not in pkt:
                return None, None
            t = pkt[TCP]
            a, b = (ip.src, t.sport), (ip.dst, t.dport)
            k = tuple(sorted([a, b]))
            server = a if t.sport < t.dport else b
            return k, server

        for pkt in pkts:
            k, server = key_of(pkt)
            if k is None:
                continue
            sess = sessions.get(k)
            if sess is None:
                sess = sessions[k] = {"server": server, "starttls": False, "app_protocol": APP_PORTS.get(server[1], "unknown"),
                                      "offered": [], "offered_groups": [], "client_versions": [], "negotiated": None,
                                      "version": None, "kex_group": None, "sni": None, "certs": [], "smtp_banner": None}
                order.append(k)
            raw = bytes(pkt[Raw].load) if Raw in pkt else b""
            if raw and not sess["negotiated"]:
                text = raw[:200].decode("ascii", "replace")
                if re.match(r"^(220|250|EHLO|HELO|STARTTLS|\* OK|a\d+ STARTTLS|\+OK|STLS)", text, re.I):
                    if "STARTTLS" in text.upper() or "STLS" in text.upper():
                        sess["starttls"] = True
                    if text.startswith("220") and sess["smtp_banner"] is None:
                        sess["smtp_banner"] = text.strip().splitlines()[0]
                        sess["app_protocol"] = "smtp"
                    if text.startswith("* OK"):
                        sess["app_protocol"] = "imap"
                    if text.startswith("+OK"):
                        sess["app_protocol"] = "pop3"
            # parse TLS records from raw payload (scapy dissects TCP payload as TLS only on known ports)
            tls = None
            if TLS in pkt:
                tls = pkt[TLS]
            elif raw[:1] in (b"\x16", b"\x17", b"\x15", b"\x14") and raw[1:2] == b"\x03":
                try:
                    tls = TLS(raw)
                except Exception:
                    tls = None
            while tls is not None:
                for msg in getattr(tls, "msg", []) or []:
                    if isinstance(msg, TLSClientHello):
                        sess["offered"] = [_suite_name(c) for c in (msg.ciphers or [])]
                        sess["offered_groups"] = _ext_groups(msg)
                        sess["client_versions"] = _ext_versions(msg) or [VERSIONS.get(msg.version, str(msg.version))]
                        sess["sni"] = _sni(msg) or sess["sni"]
                    elif isinstance(msg, TLSServerHello):
                        sess["negotiated"] = _suite_name(msg.cipher)
                        sv = _ext_versions(msg)
                        sess["version"] = sv[0] if sv else VERSIONS.get(msg.version, str(msg.version))
                        sess["kex_group"] = _ext_keyshare_group(msg)
                    elif isinstance(msg, TLSCertificate):
                        for c in getattr(msg, "certs", None) or []:
                            cert = c[1] if isinstance(c, (tuple, list)) else c
                            der = getattr(cert, "der", None)
                            if der is None and hasattr(cert, "x509Cert"):
                                der = bytes(cert.x509Cert)
                            if der:
                                sess["certs"].append(bytes(der))
                tls = tls.payload if isinstance(getattr(tls, "payload", None), TLS) else None

        out: list[RawFinding] = []
        ctx = {"zone": target.zone, "pcap": True}
        tshark = self._tshark(path) if target.props.get("use_tshark", True) else None
        for k in order:
            s = sessions[k]
            if not (s["offered"] or s["negotiated"]):
                continue
            host, port = s["server"]
            loc = f"pcap://{path.name}#{host}:{port}"
            props = {"type": "tls", "versions": [s["version"]] if s["version"] else s["client_versions"],
                     "client_versions": s["client_versions"], "cipher_suites": [s["negotiated"]] if s["negotiated"] else [],
                     "offered_suites": s["offered"], "offered_groups": s["offered_groups"], "kex_group": s["kex_group"],
                     "pq_kex": (s["kex_group"] or "") in ("X25519MLKEM768", "SecP256r1MLKEM768", "X25519Kyber768Draft00"),
                     "sni": s["sni"], "starttls": s["starttls"], "app_protocol": s["app_protocol"], "server": f"{host}:{port}",
                     "negotiated": {"version": s["version"], "cipher_suite": s["negotiated"]}, "api": "pcap"}
            if tshark is not None:
                props["corroborated_by_tshark"] = s["negotiated"] in tshark.get("suites", set()) if s["negotiated"] else False
            out.append(RawFinding("pcap", "protocol", "TLS", loc, None, f"{s['version']} {s['negotiated']} {'STARTTLS' if s['starttls'] else ''}".strip(),
                                  "high" if s["negotiated"] else "medium", target.name, props, dict(ctx)))
            for suite in props["cipher_suites"]:
                for alg, prim, mode in suite_algorithms(suite):
                    out.append(RawFinding("pcap", "algorithm", alg, loc, None, suite, "high", target.name,
                                          {"primitive": prim, "mode": mode, "suite": suite, "api": "negotiated"}, dict(ctx)))
            if s["kex_group"]:
                alg = kb.canonicalise(s["kex_group"]) or ("ECDH" if s["kex_group"].startswith("secp") else None)
                if alg:
                    out.append(RawFinding("pcap", "algorithm", alg, loc, None, f"key_share {s['kex_group']}", "high", target.name,
                                          {"primitive": "combiner" if alg == "X25519MLKEM768" else "key-agree", "curve": s["kex_group"], "api": "negotiated-kex"}, dict(ctx)))
            for der in s["certs"]:
                try:
                    info = parse_x509(der, kb)
                except Exception:
                    continue
                info["extension"] = ".der"
                out.append(RawFinding("pcap", "certificate", info.get("cn") or info["subject"], loc, None,
                                      f"CN={info.get('cn')} issuer={info['issuer'][:60]}", "high", target.name, info, dict(ctx)))
                out.append(RawFinding("pcap", "algorithm", info["public_key_algorithm"], loc, None, "certificate public key", "high",
                                      target.name, {"key_size": info.get("key_size"), "curve": info.get("curve"), "api": "x509-public-key",
                                                    "primitive": "signature" if info["public_key_algorithm"] in ("ECDSA", "Ed25519") else "pke",
                                                    "certificate": info["sha256_fingerprint"]}, dict(ctx)))
                if info.get("signature_hash"):
                    out.append(RawFinding("pcap", "algorithm", info["signature_hash"], loc, None, "certificate signature hash", "high",
                                          target.name, {"primitive": "hash", "api": "x509-signature"}, dict(ctx)))
        return out

    @staticmethod
    def _tshark(path: Path) -> dict | None:
        exe = tools.find("tshark")
        if not exe:
            return None
        try:
            r = subprocess.run([str(exe), "-r", str(path), "-Y", "tls.handshake.type == 2", "-T", "fields",
                                "-e", "tls.handshake.ciphersuite", "-e", "tls.handshake.version"],
                               capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace")
        except Exception:
            return None
        suites = set()
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if parts and parts[0]:
                for c in parts[0].split(","):
                    try:
                        suites.add(_suite_name(int(c, 16) if c.startswith("0x") else int(c)))
                    except ValueError:
                        pass
        return {"suites": suites}
