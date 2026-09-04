"""Build the crypto-zoo artefacts that cannot live in git as source: certificates, keystores, a compiled
binary, a synthetic OCI image tar, and pcaps. Ground truth for every artefact is in tests/fixtures/zoo/truth.yaml.

Usage: python scripts/build_zoo.py [--out tests/fixtures/zoo]  (also: `ecdat zoo build`)"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
ZOO = ROOT / "tests" / "fixtures" / "zoo"


# ------------------------------------------------------------------------------------------------
# certificates
# ------------------------------------------------------------------------------------------------
def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ECDAT Zoo"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, issuer_key, cn: str, issuer_cn: str, hash_alg, days: int, not_before: dt.datetime | None = None,
          is_ca: bool = False, san: list[str] | None = None) -> x509.Certificate:
    nb = not_before or dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(nb + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True))
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    return b.sign(issuer_key, hash_alg)


def build_certs(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    truth = {}
    ca_key = rsa.generate_private_key(65537, 4096)
    ca = _cert(ca_key, ca_key, "ECDAT Zoo Root CA", "ECDAT Zoo Root CA", hashes.SHA256(), 3650, is_ca=True)
    (out / "ca_rsa4096.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    truth["ca_rsa4096.crt"] = {"public_key_algorithm": "RSA", "key_size": 4096, "signature_hash": "SHA-256", "is_ca": True}

    k1 = rsa.generate_private_key(65537, 2048)
    c1 = _cert(k1, ca_key, "pay.zoo.local", "ECDAT Zoo Root CA", hashes.SHA256(), 365, san=["pay.zoo.local", "zoo.local"])
    (out / "rsa2048_sha256.crt").write_bytes(c1.public_bytes(serialization.Encoding.PEM))
    (out / "rsa2048_sha256.key").write_bytes(k1.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    truth["rsa2048_sha256.crt"] = {"public_key_algorithm": "RSA", "key_size": 2048, "signature_hash": "SHA-256", "cn": "pay.zoo.local"}

    k2 = ec.generate_private_key(ec.SECP256R1())
    c2 = _cert(k2, ca_key, "api.zoo.local", "ECDAT Zoo Root CA", hashes.SHA384(), 365)
    (out / "ecdsa_p256.crt").write_bytes(c2.public_bytes(serialization.Encoding.PEM))
    truth["ecdsa_p256.crt"] = {"public_key_algorithm": "ECDSA", "curve": "secp256r1", "signature_hash": "SHA-384"}

    # expired RSA-2048 cert (cryptography refuses to *sign* with SHA-1, so SHA-1 comes from the OpenSSL CLI below)
    k3 = rsa.generate_private_key(65537, 2048)
    c3 = _cert(k3, k3, "expired.zoo.local", "expired.zoo.local", hashes.SHA256(), 365,
               not_before=dt.datetime(2019, 1, 1, tzinfo=dt.timezone.utc))
    (out / "rsa2048_expired.crt").write_bytes(c3.public_bytes(serialization.Encoding.DER))
    truth["rsa2048_expired.crt"] = {"public_key_algorithm": "RSA", "key_size": 2048, "signature_hash": "SHA-256", "expired": True}
    openssl = shutil.which("openssl") or r"C:\Program Files\Git\mingw64\bin\openssl.exe"
    if Path(openssl).exists():
        r = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:1024", "-sha1", "-days", "365", "-nodes",
                            "-subj", "/C=IN/O=ECDAT Zoo/CN=legacy.zoo.local", "-keyout", str(out / "rsa1024.key"),
                            "-out", str(out / "rsa1024_sha1.der"), "-outform", "DER"], capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            truth["rsa1024_sha1.der"] = {"public_key_algorithm": "RSA", "key_size": 1024, "signature_hash": "SHA-1"}
        else:
            print("openssl sha1 cert failed:", r.stderr[:300], file=sys.stderr)

    (out / "bundle.pem").write_bytes(c1.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    truth["bundle.pem"] = {"certs": 2}

    p12 = pkcs12.serialize_key_and_certificates(b"pay", k1, c1, [ca], serialization.BestAvailableEncryption(b"zoo"))
    (out / "pay.p12").write_bytes(p12)
    truth["pay.p12"] = {"password": "zoo", "public_key_algorithm": "RSA", "key_size": 2048, "private_key": True}

    keytool = shutil.which("keytool") or r"C:\Program Files\Java\jdk-17\bin\keytool.exe"
    jks = out / "keystore.jks"
    if jks.exists():
        jks.unlink()
    if Path(keytool).exists():
        subprocess.run([keytool, "-genkeypair", "-keyalg", "RSA", "-keysize", "2048", "-alias", "pay", "-dname",
                        "CN=jks.zoo.local, O=ECDAT Zoo, C=IN", "-storepass", "zoopass", "-keypass", "zoopass",
                        "-keystore", str(jks), "-validity", "365", "-sigalg", "SHA256withRSA", "-storetype", "JKS"],
                       capture_output=True, timeout=120)
        subprocess.run([keytool, "-importcert", "-noprompt", "-alias", "zooca", "-file", str(out / "ca_rsa4096.crt"),
                        "-storepass", "zoopass", "-keystore", str(jks), "-storetype", "JKS"], capture_output=True, timeout=120)
        # and a PKCS#12-format store with a .jks name, which is what modern keytool produces by default
        p12jks = out / "modern.jks"
        if p12jks.exists():
            p12jks.unlink()
        subprocess.run([keytool, "-genkeypair", "-keyalg", "EC", "-groupname", "secp256r1", "-alias", "api", "-dname",
                        "CN=api.zoo.local, O=ECDAT Zoo, C=IN", "-storepass", "zoopass", "-keypass", "zoopass",
                        "-keystore", str(p12jks), "-validity", "365"], capture_output=True, timeout=120)
        truth["modern.jks"] = {"password": "zoopass", "private_key_algorithm": "ECDSA", "format": "PKCS#12"}
        truth["keystore.jks"] = {"password": "zoopass", "private_key_algorithm": "RSA", "key_size": 2048}
    return truth


# ------------------------------------------------------------------------------------------------
# binary (Go build of the zoo gateway) + synthetic constants blob
# ------------------------------------------------------------------------------------------------
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
])
# SHA-256 initial hash values H0..H7 (findcrypt3 SHA256_Constants) in both byte orders, plus the first K constants
SHA256_K = (bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
            + bytes.fromhex("67e6096a85ae67bb72f36e3a3af54fa57f520e518c68059babd9831f19cde05b")
            + bytes.fromhex("428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5"))
# MD5 init constants A,B,C,D in both byte orders plus T[1..4]
MD5_T = (bytes.fromhex("67452301efcdab8998badcfe10325476") + bytes.fromhex("0123456789abcdeffedcba9876543210")
         + bytes.fromhex("78a46ad7" "56b7c7e8" "db702024" "eecebdc1"))


def build_binaries(out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    truth = {}
    blob = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 9 + b"ZOO-SYNTHETIC-BINARY\x00OpenSSL 1.1.1w  11 Sep 2023\x00" \
           + b"\x00" * 64 + AES_SBOX + b"\x00" * 32 + SHA256_K + b"\x00" * 32 + MD5_T + b"\x00" * 32 \
           + b"RSA_public_encrypt\x00EVP_sha256\x00crypto/rsa.GenerateKey\x00"
    (out / "libzoocrypto.so").write_bytes(blob)
    truth["libzoocrypto.so"] = {"algorithms": ["AES", "SHA-256", "MD5"], "library": "openssl", "version": "1.1.1w"}
    go = shutil.which("go") or r"C:\Program Files\Go\bin\go.exe"
    src = ZOO / "src" / "go"
    if Path(go).exists() and (src / "main.go").exists():
        env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0", GOFLAGS="-mod=mod")
        exe = out / "zoobin"
        r = subprocess.run([go, "build", "-o", str(exe), "."], cwd=str(src), capture_output=True, text=True, timeout=600, env=env)
        if r.returncode == 0:
            truth["zoobin"] = {"algorithms": ["RSA", "ECDSA", "SHA-256", "AES", "TLS"], "go": True}
        else:
            print("go build failed:", r.stderr[:400], file=sys.stderr)
    return truth


# ------------------------------------------------------------------------------------------------
# synthetic OCI image tar
# ------------------------------------------------------------------------------------------------
def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1700000000
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def build_image(out: Path, certs: Path, bins: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    layer_files = {
        "etc/ssl/certs/pay.crt": (certs / "rsa2048_sha256.crt").read_bytes(),
        "etc/ssl/certs/legacy.der": (certs / "rsa2048_expired.crt").read_bytes(),
        "etc/nginx/nginx.conf": (ZOO / "src" / "nginx" / "nginx.conf").read_bytes(),
        "etc/ssl/openssl.cnf": (ZOO / "src" / "nginx" / "openssl.cnf").read_bytes(),
        "usr/lib/libcrypto.so.1.1": (bins / "libzoocrypto.so").read_bytes(),
        "app/requirements.txt": (ZOO / "src" / "python" / "requirements.txt").read_bytes(),
        "app/payments/auth.py": (ZOO / "src" / "python" / "payments" / "auth.py").read_bytes(),
    }
    layer = gzip.compress(_tar_bytes(layer_files), mtime=0)
    layer_digest = "sha256:" + hashlib.sha256(layer).hexdigest()
    diff_id = "sha256:" + hashlib.sha256(gzip.decompress(layer)).hexdigest()
    config = json.dumps({"architecture": "amd64", "os": "linux", "created": "2026-09-05T00:00:00Z",
                         "config": {"Env": ["PATH=/usr/bin"], "Cmd": ["/app/run"]},
                         "rootfs": {"type": "layers", "diff_ids": [diff_id]}}).encode()
    config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": len(config)},
                           "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_digest, "size": len(layer)}]}).encode()
    manifest_digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
    index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest_digest,
                                       "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": "zoo/pay-image:1.0"}}]}).encode()
    files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": index,
        f"blobs/sha256/{manifest_digest[7:]}": manifest,
        f"blobs/sha256/{config_digest[7:]}": config,
        f"blobs/sha256/{layer_digest[7:]}": layer,
    }
    (out / "zoo-oci.tar").write_bytes(_tar_bytes(files))
    # docker-save style too (manifest.json + layer dirs)
    docker_files = {
        "manifest.json": json.dumps([{"Config": "config.json", "RepoTags": ["zoo/pay-image:1.0"], "Layers": ["layer1/layer.tar"]}]).encode(),
        "config.json": config,
        "layer1/layer.tar": gzip.decompress(layer),
    }
    (out / "zoo-docker.tar").write_bytes(_tar_bytes(docker_files))
    return {"zoo-oci.tar": {"certs": 2, "nginx": True, "openssl_cnf": True, "binary": "libcrypto.so.1.1"},
            "zoo-docker.tar": {"certs": 2}}


# ------------------------------------------------------------------------------------------------
# pcaps (scapy)
# ------------------------------------------------------------------------------------------------
def build_pcaps(out: Path, certs: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    from scapy.all import IP, TCP, Ether, Raw, wrpcap, load_layer
    load_layer("tls")
    from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello, TLSCertificate
    from scapy.layers.tls.extensions import TLS_Ext_ServerName, ServerName, TLS_Ext_SupportedGroups, TLS_Ext_SupportedVersion_CH
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.cert import Cert

    cert_pem = (certs / "rsa2048_sha256.crt").read_bytes()
    truth = {}

    def stream(client, server, sport, dport, payloads: list[tuple[str, bytes]]):
        pkts = []
        seq = {"c": 1000, "s": 5000}
        for who, data in payloads:
            if who == "c":
                p = Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA", seq=seq["c"], ack=seq["s"]) / Raw(data)
                seq["c"] += len(data)
            else:
                p = Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA", seq=seq["s"], ack=seq["c"]) / Raw(data)
                seq["s"] += len(data)
            pkts.append(p)
        return pkts

    # 1) HTTPS: TLS 1.2 ClientHello -> ServerHello (ECDHE-RSA-AES256-GCM-SHA384) -> Certificate
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xc030, 0xc02f, 0x1301, 0x000a],
                                 ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"pay.zoo.local")]),
                                      TLS_Ext_SupportedGroups(groups=[29, 23])])])
    sh = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xc030)])
    ct = TLS(msg=[TLSCertificate(certs=[Cert(cert_pem)])])
    https = stream("10.0.0.5", "10.0.0.80", 51000, 443, [("c", bytes(ch)), ("s", bytes(sh)), ("s", bytes(ct))])
    wrpcap(str(out / "tls_handshake.pcap"), https)
    truth["tls_handshake.pcap"] = {"cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "version": "TLSv1.2",
                                   "sni": "pay.zoo.local", "cert_cn": "pay.zoo.local"}

    # 2) SMTP STARTTLS: banner, EHLO, STARTTLS, then a TLS 1.0 handshake selecting 3DES
    ch2 = TLS(msg=[TLSClientHello(version=0x0301, ciphers=[0x000a, 0x0005, 0x002f])])
    sh2 = TLS(msg=[TLSServerHello(version=0x0301, cipher=0x000a)])
    smtp = stream("10.0.0.7", "10.0.0.25", 52000, 25, [
        ("s", b"220 mail.zoo.local ESMTP ready\r\n"), ("c", b"EHLO client.zoo.local\r\n"),
        ("s", b"250-mail.zoo.local\r\n250-STARTTLS\r\n250 OK\r\n"), ("c", b"STARTTLS\r\n"),
        ("s", b"220 2.0.0 Ready to start TLS\r\n"), ("c", bytes(ch2)), ("s", bytes(sh2)),
    ])
    wrpcap(str(out / "smtp_starttls.pcap"), smtp)
    truth["smtp_starttls.pcap"] = {"cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "version": "TLSv1.0", "starttls": True,
                                   "app_protocol": "smtp"}
    return truth


# ------------------------------------------------------------------------------------------------
def build_all(zoo: Path = ZOO) -> dict:
    truth = {"certs": build_certs(zoo / "certs")}
    truth["bin"] = build_binaries(zoo / "bin")
    truth["images"] = build_image(zoo / "images", zoo / "certs", zoo / "bin")
    truth["pcaps"] = build_pcaps(zoo / "pcaps", zoo / "certs")
    (zoo / "artefacts_truth.json").write_text(json.dumps(truth, indent=2, default=str), encoding="utf-8")
    return truth


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ZOO))
    a = ap.parse_args()
    t = build_all(Path(a.out))
    print(json.dumps({k: sorted(v.keys()) for k, v in t.items()}, indent=2))
