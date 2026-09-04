"""Protocol collector: what a live server *actually negotiates*.
TLS: CryptoLyzer (versions, cipher suites, groups, certificates) when importable, else the ssl module handshake;
plus a raw ClientHello probe (pure Python) that offers X25519MLKEM768 and reads the ServerHello key_share group,
so post-quantum key exchange support is detected even without CryptoLyzer.
SSH: banner + KEXINIT name-lists (kex, host-key, ciphers, MACs), no auth attempted."""
from __future__ import annotations

import os
import socket
import ssl
import struct
from pathlib import Path

from ecdat.collectors.base import Collector, Target
from ecdat.collectors.certificate import parse_x509
from ecdat.collectors.source import suite_algorithms
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

TIMEOUT = float(os.environ.get("ECDAT_NET_TIMEOUT", "8"))
GROUPS = {0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1", 0x001d: "x25519", 0x001e: "x448",
          0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x11ec: "X25519MLKEM768", 0x11eb: "SecP256r1MLKEM768",
          0x6399: "X25519Kyber768Draft00", 0x0200: "ML-KEM-512", 0x0201: "ML-KEM-768", 0x0202: "ML-KEM-1024"}
PQ_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "X25519Kyber768Draft00", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
TLS13_SUITES = {0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256"}


def parse_endpoints(target: Target) -> list[tuple[str, int, str]]:
    eps: list[tuple[str, int, str]] = []
    raw = list(target.props.get("endpoints") or [])
    p = Path(target.path) if target.path else None
    if p and p.is_file():
        raw += [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()]
    elif target.path and not (p and p.exists()):
        raw.append(target.path)
    for line in raw:
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        hp = parts[0]
        kind = parts[1].lower() if len(parts) > 1 else ("ssh" if hp.endswith(":22") else "tls")
        host, _, port = hp.rpartition(":")
        if not host:
            host, port = hp, ("22" if kind == "ssh" else "443")
        eps.append((host.strip("[]"), int(port), kind))
    return eps


# ------------------------------------------------------------------------------------------------
# raw TLS 1.3 ClientHello with a PQ hybrid group offered -> ServerHello key_share group
# ------------------------------------------------------------------------------------------------
def _client_hello(sni: str, groups: list[int]) -> bytes:
    rnd = os.urandom(32)
    session = os.urandom(32)
    suites = b"".join(struct.pack("!H", s) for s in (0x1302, 0x1301, 0x1303, 0xc030, 0xc02f, 0xc02c, 0xc02b))
    host = sni.encode()
    ext_sni = struct.pack("!HH", 0, 5 + len(host)) + struct.pack("!H", 3 + len(host)) + b"\x00" + struct.pack("!H", len(host)) + host
    grp = b"".join(struct.pack("!H", g) for g in groups)
    ext_groups = struct.pack("!HH", 10, 2 + len(grp)) + struct.pack("!H", len(grp)) + grp
    sig = b"".join(struct.pack("!H", s) for s in (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201))
    ext_sig = struct.pack("!HH", 13, 2 + len(sig)) + struct.pack("!H", len(sig)) + sig
    ext_ver = struct.pack("!HH", 43, 3) + b"\x02\x03\x04"
    ext_psk = struct.pack("!HH", 45, 2) + b"\x01\x01"
    # key_share: x25519 only (the server may pick a PQ group via HelloRetryRequest, which still reveals support)
    ks = struct.pack("!HH", 0x001d, 32) + os.urandom(32)
    ext_ks = struct.pack("!HH", 51, 2 + len(ks)) + struct.pack("!H", len(ks)) + ks
    exts = ext_sni + ext_groups + ext_sig + ext_ver + ext_psk + ext_ks
    body = b"\x03\x03" + rnd + struct.pack("!B", len(session)) + session + struct.pack("!H", len(suites)) + suites \
        + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def _read_record(sock: socket.socket) -> tuple[int, bytes] | None:
    hdr = b""
    while len(hdr) < 5:
        chunk = sock.recv(5 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    ctype, _ver, ln = hdr[0], hdr[1:3], struct.unpack("!H", hdr[3:5])[0]
    body = b""
    while len(body) < ln:
        chunk = sock.recv(ln - len(body))
        if not chunk:
            break
        body += chunk
    return ctype, body


def probe_pq_groups(host: str, port: int, sni: str | None = None) -> dict:
    """Offer PQ hybrid groups; report the group the server selected (or requested via HelloRetryRequest)."""
    out = {"offered": [GROUPS[g] for g in (0x11ec, 0x11eb, 0x001d, 0x0017)], "selected_group": None, "pq_kex": False,
           "server_version": None, "cipher_suite": None, "hrr": False}
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            s.sendall(_client_hello(sni or host, [0x11ec, 0x11eb, 0x001d, 0x0017]))
            rec = _read_record(s)
            if not rec:
                return out
            ctype, body = rec
            if ctype != 0x16 or not body or body[0] != 2:
                out["alert"] = body[:2].hex() if ctype == 0x15 else None
                return out
            p = 4  # handshake header
            ver = body[p:p + 2]; p += 2
            random = body[p:p + 32]; p += 32
            out["hrr"] = random == bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
            sid_len = body[p]; p += 1 + sid_len
            suite = struct.unpack("!H", body[p:p + 2])[0]; p += 2
            out["cipher_suite"] = TLS13_SUITES.get(suite, f"0x{suite:04x}")
            p += 1  # compression
            if p + 2 <= len(body):
                ext_len = struct.unpack("!H", body[p:p + 2])[0]; p += 2
                end = p + ext_len
                while p + 4 <= end:
                    et, el = struct.unpack("!HH", body[p:p + 4]); p += 4
                    ev = body[p:p + el]; p += el
                    if et == 43 and len(ev) >= 2:
                        out["server_version"] = "TLSv1.3" if ev[:2] == b"\x03\x04" else f"0x{ev[:2].hex()}"
                    if et == 51 and len(ev) >= 2:
                        g = struct.unpack("!H", ev[:2])[0]
                        out["selected_group"] = GROUPS.get(g, f"0x{g:04x}")
            if out["server_version"] is None:
                out["server_version"] = "TLSv1.2" if ver == b"\x03\x03" else f"0x{ver.hex()}"
            out["pq_kex"] = out["selected_group"] in PQ_GROUPS
    except (OSError, ssl.SSLError, struct.error) as exc:
        out["error"] = str(exc)[:120]
    return out


# ------------------------------------------------------------------------------------------------
def ssl_handshake(host: str, port: int, sni: str | None = None, starttls: str | None = None) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    out = {}
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        if starttls == "smtp":
            raw.recv(1024); raw.sendall(b"EHLO ecdat.local\r\n"); raw.recv(4096); raw.sendall(b"STARTTLS\r\n"); raw.recv(1024)
        elif starttls == "imap":
            raw.recv(1024); raw.sendall(b"a1 STARTTLS\r\n"); raw.recv(1024)
        elif starttls == "pop3":
            raw.recv(1024); raw.sendall(b"STLS\r\n"); raw.recv(1024)
        with ctx.wrap_socket(raw, server_hostname=sni or host) as s:
            out["version"] = s.version()
            c = s.cipher()
            out["cipher_suite"] = c[0] if c else None
            out["cipher_bits"] = c[2] if c else None
            der = s.getpeercert(binary_form=True)
            out["cert_der"] = der
    return out


def cryptolyzer_tls(host: str, port: int) -> dict | None:
    try:
        from cryptolyzer.common.transfer import L4TransferSocketParams
        from cryptolyzer.tls.client import L7ClientTlsBase
        from cryptolyzer.tls.ciphers import AnalyzerCipherSuites
        from cryptolyzer.tls.versions import AnalyzerVersions
        from cryptolyzer.tls.curves import AnalyzerCurves
        from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion
    except Exception:
        return None
    try:
        params = L4TransferSocketParams(timeout=TIMEOUT)
        client = L7ClientTlsBase.from_scheme("tls", host, port, l4_socket_params=params)
        versions = AnalyzerVersions().analyze(client, None)
        out = {"versions": [str(v) for v in versions.versions], "cipher_suites": [], "groups": []}
        best = None
        for v in versions.versions:
            best = v
        if best is not None:
            ciphers = AnalyzerCipherSuites().analyze(client, best)
            out["cipher_suites"] = [c.name for c in ciphers.cipher_suites]
            try:
                curves = AnalyzerCurves().analyze(client, best)
                out["groups"] = [c.name for c in curves.curves]
            except Exception:
                pass
        return out
    except Exception:
        return None


def ssh_kexinit(host: str, port: int) -> dict:
    out = {"banner": None, "kex": [], "hostkey": [], "ciphers": [], "macs": [], "pq_kex": False}
    with socket.create_connection((host, port), timeout=TIMEOUT) as s:
        banner = b""
        while not banner.endswith(b"\n"):
            ch = s.recv(1)
            if not ch:
                break
            banner += ch
        out["banner"] = banner.decode("ascii", "replace").strip()
        # our banner + KEXINIT (minimal but valid) in one write, so servers that wait for the client speak first
        cookie = os.urandom(16)
        lists = [b"curve25519-sha256", b"ssh-ed25519", b"aes256-gcm@openssh.com", b"aes256-gcm@openssh.com",
                 b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b""]
        payload = b"\x14" + cookie + b"".join(struct.pack("!I", len(x)) + x for x in lists) + b"\x00" + b"\x00\x00\x00\x00"
        pad = 8 - ((len(payload) + 5) % 8)
        pad = pad + 8 if pad < 4 else pad
        pkt = struct.pack("!IB", len(payload) + pad + 1, pad) + payload + os.urandom(pad)
        s.sendall(b"SSH-2.0-ecdat_0.1\r\n" + pkt)
        data = b""
        s.settimeout(TIMEOUT)
        while len(data) < 4 or len(data) < struct.unpack("!I", data[:4])[0] + 4:
            try:
                chunk = s.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 200000:
                break
        if len(data) >= 6 and data[5] == 0x14:
            p = 6 + 16
            names = []
            for _ in range(10):
                ln = struct.unpack("!I", data[p:p + 4])[0]; p += 4
                names.append(data[p:p + ln].decode("ascii", "replace")); p += ln
            out["kex"] = names[0].split(",") if names[0] else []
            out["hostkey"] = names[1].split(",") if names[1] else []
            out["ciphers"] = sorted(set(names[2].split(",")) | set(names[3].split(","))) if names[2] else []
            out["macs"] = sorted(set(names[4].split(",")) | set(names[5].split(","))) if names[4] else []
            out["pq_kex"] = any(k.startswith(("mlkem", "sntrup761x25519")) for k in out["kex"])
    return out


class ProtocolCollector(Collector):
    name = "protocol"
    kinds = {"endpoints"}

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        out: list[RawFinding] = []
        for host, port, kind in parse_endpoints(target):
            loc = f"{kind}://{host}:{port}"
            ctx = {"zone": target.zone, "live": True}
            try:
                if kind == "ssh":
                    out += self._ssh(host, port, loc, target, kb, ctx)
                else:
                    starttls = kind if kind in ("smtp", "imap", "pop3") else None
                    out += self._tls(host, port, loc, target, kb, ctx, starttls)
            except Exception as exc:
                out.append(RawFinding("protocol", "protocol", "TLS" if kind != "ssh" else "SSH", loc, None, str(exc)[:200], "low",
                                      target.name, {"type": kind, "error": str(exc)[:200], "reachable": False}, ctx))
        return out

    def _tls(self, host, port, loc, target, kb, ctx, starttls) -> list[RawFinding]:
        out: list[RawFinding] = []
        hs = ssl_handshake(host, port, starttls=starttls)
        props = {"type": "tls", "versions": [hs["version"]] if hs.get("version") else [], "negotiated": {"version": hs.get("version"),
                 "cipher_suite": hs.get("cipher_suite"), "bits": hs.get("cipher_bits")}, "cipher_suites": [hs["cipher_suite"]] if hs.get("cipher_suite") else [],
                 "starttls": starttls, "reachable": True, "api": "live-handshake"}
        if not starttls:
            pq = probe_pq_groups(host, port)
            props["pq_probe"] = pq
            props["pq_kex"] = pq.get("pq_kex", False)
            props["kex_group"] = pq.get("selected_group")
            props["kex_groups_offered"] = pq.get("offered")
            cl = cryptolyzer_tls(host, port) if target.props.get("use_cryptolyzer", True) else None
            if cl:
                props["versions"] = sorted(set(props["versions"]) | set(cl.get("versions", [])))
                props["cipher_suites"] = sorted(set(props["cipher_suites"]) | set(cl.get("cipher_suites", [])))
                props["kex_groups_supported"] = cl.get("groups", [])
                props["api"] = "cryptolyzer+live-handshake"
        out.append(RawFinding("protocol", "protocol", "TLS", loc, None, f"{hs.get('version')} {hs.get('cipher_suite')}", "high",
                              target.name, props, dict(ctx)))
        # negotiated suite -> algorithms; key-exchange group -> algorithm
        for suite in props["cipher_suites"]:
            for alg, prim, mode in suite_algorithms(suite):
                out.append(RawFinding("protocol", "algorithm", alg, loc, None, suite, "high", target.name,
                                      {"primitive": prim, "mode": mode, "suite": suite, "api": "negotiated"}, dict(ctx)))
        grp = props.get("kex_group")
        if grp:
            alg = kb.canonicalise(grp) or ("ECDH" if grp.startswith("secp") else ("DH" if grp.startswith("ffdhe") else None))
            if alg:
                out.append(RawFinding("protocol", "algorithm", alg, loc, None, f"key_share {grp}", "high", target.name,
                                      {"primitive": "combiner" if alg == "X25519MLKEM768" else "key-agree", "curve": grp, "api": "negotiated-kex"}, dict(ctx)))
        if hs.get("cert_der"):
            try:
                info = parse_x509(hs["cert_der"], kb)
                info["extension"] = ".der"
                out.append(RawFinding("protocol", "certificate", info.get("cn") or info["subject"], loc, None,
                                      f"CN={info.get('cn')} issuer={info['issuer'][:60]}", "high", target.name, info, dict(ctx)))
                out.append(RawFinding("protocol", "algorithm", info["public_key_algorithm"], loc, None, "server certificate public key",
                                      "high", target.name, {"key_size": info.get("key_size"), "curve": info.get("curve"),
                                                            "primitive": "signature" if info["public_key_algorithm"] in ("ECDSA", "Ed25519") else "pke",
                                                            "api": "x509-public-key", "certificate": info["sha256_fingerprint"]}, dict(ctx)))
                if info.get("signature_hash"):
                    out.append(RawFinding("protocol", "algorithm", info["signature_hash"], loc, None, "server certificate signature hash",
                                          "high", target.name, {"primitive": "hash", "api": "x509-signature"}, dict(ctx)))
            except Exception:
                pass
        return out

    def _ssh(self, host, port, loc, target, kb, ctx) -> list[RawFinding]:
        info = ssh_kexinit(host, port)
        props = {"type": "ssh", "versions": ["SSH-2.0"], "banner": info["banner"], "kex": info["kex"], "hostkey": info["hostkey"],
                 "cipher_suites": info["ciphers"], "macs": info["macs"], "pq_kex": info["pq_kex"], "reachable": True, "api": "kexinit"}
        out = [RawFinding("protocol", "protocol", "SSH", loc, None, info["banner"] or "", "high", target.name, props, dict(ctx))]
        for lst, prim in ((info["kex"], "key-agree"), (info["hostkey"], "signature"), (info["ciphers"], "block-cipher"), (info["macs"], "mac")):
            for name in lst:
                alg = kb.canonicalise(name.split("@")[0])
                if alg:
                    p = {"primitive": kb.info(alg).get("primitive", prim), "raw": name, "api": "kexinit"}
                    out.append(RawFinding("protocol", "algorithm", alg, loc, None, name, "high", target.name, p, dict(ctx)))
        return out
