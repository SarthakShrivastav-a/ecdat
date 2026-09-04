import socket
import ssl
import struct
import threading
from pathlib import Path

import pytest

from ecdat.collectors.base import Target
from ecdat.collectors.protocol import ProtocolCollector, parse_endpoints, probe_pq_groups
from ecdat.knowledge import KnowledgeBase

kb = KnowledgeBase()


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    from scripts.build_zoo import build_certs
    d = tmp_path_factory.mktemp("srv")
    build_certs(d)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(d / "rsa2048_sha256.crt"), str(d / "rsa2048_sha256.key"))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.settimeout(1)
                    try:
                        s.recv(1)
                    except Exception:
                        pass
            except Exception:
                pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield port
    stop.set()
    srv.close()


@pytest.fixture(scope="module")
def ssh_server():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()
    lists = [b"curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256", b"ssh-ed25519,rsa-sha2-512",
             b"aes256-gcm@openssh.com,aes128-ctr", b"aes256-gcm@openssh.com,aes128-ctr", b"hmac-sha2-256", b"hmac-sha2-256",
             b"none", b"none", b"", b""]
    payload = b"\x14" + b"\x00" * 16 + b"".join(struct.pack("!I", len(x)) + x for x in lists) + b"\x00" + b"\x00\x00\x00\x00"
    pad = 8 - ((len(payload) + 5) % 8)
    pad = pad + 8 if pad < 4 else pad
    pkt = struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad

    def serve():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            try:
                conn.sendall(b"SSH-2.0-zoo_fake\r\n")
                conn.settimeout(2)
                got = b""
                while b"\x14" not in got[got.find(b"\n") + 1:] and len(got) < 4096:   # wait for the client KEXINIT
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                conn.sendall(pkt)
                conn.settimeout(1)
                try:
                    conn.recv(1)   # let the client finish reading before we close (avoids RST discarding data)
                except Exception:
                    pass
            except Exception:
                pass
            finally:
                conn.close()
    threading.Thread(target=serve, daemon=True).start()
    yield port
    stop.set()
    srv.close()


def test_parse_endpoints(tmp_path):
    f = tmp_path / "eps.txt"
    f.write_text("example.com:443 tls\n# comment\nmail.zoo.local:25 smtp\nhost.zoo.local:22\n")
    eps = parse_endpoints(Target("endpoints", str(f), "eps", "external"))
    assert eps == [("example.com", 443, "tls"), ("mail.zoo.local", 25, "smtp"), ("host.zoo.local", 22, "ssh")]


def test_live_tls_probe(tls_server):
    t = Target("endpoints", "", "edge", "external", props={"endpoints": [f"127.0.0.1:{tls_server} tls"], "use_cryptolyzer": False})
    fs = ProtocolCollector().collect(t, kb)
    proto = [f for f in fs if f.asset_type == "protocol"][0]
    assert proto.props["reachable"] and proto.props["negotiated"]["version"] in ("TLSv1.3", "TLSv1.2")
    assert proto.props["pq_kex"] is False and proto.props["kex_group"] in ("x25519", "secp256r1", None)
    cert = [f for f in fs if f.asset_type == "certificate"][0]
    assert cert.props["cn"] == "pay.zoo.local" and cert.props["key_size"] == 2048
    names = {f.name for f in fs if f.asset_type == "algorithm"}
    assert "RSA" in names and ("AES-256" in names or "AES-128" in names or "ChaCha20" in names)
    assert all(f.context["live"] and f.context["zone"] == "external" for f in fs)


def test_pq_probe_reports_group(tls_server):
    pq = probe_pq_groups("127.0.0.1", tls_server)
    assert pq["offered"][0] == "X25519MLKEM768"
    assert "error" not in pq or pq["selected_group"] is None


def test_ssh_kexinit(ssh_server):
    t = Target("endpoints", "", "bastion", "internal", props={"endpoints": [f"127.0.0.1:{ssh_server} ssh"]})
    fs = ProtocolCollector().collect(t, kb)
    proto = [f for f in fs if f.asset_type == "protocol"][0]
    assert proto.props.get("reachable"), proto.props.get("error")
    assert proto.name == "SSH" and "curve25519-sha256" in proto.props["kex"] and proto.props["pq_kex"] is False
    names = {f.name for f in fs if f.asset_type == "algorithm"}
    assert {"X25519", "ECDH", "DH", "Ed25519", "RSA", "AES-256", "AES-128", "HMAC"} <= names


def test_unreachable_endpoint_is_reported_not_raised():
    t = Target("endpoints", "", "dead", "internal", props={"endpoints": ["127.0.0.1:1 tls"]})
    fs = ProtocolCollector().collect(t, kb)
    assert len(fs) == 1 and fs[0].props["reachable"] is False and fs[0].confidence == "low"
