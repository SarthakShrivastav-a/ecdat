"""Binary collector (best-effort, medium confidence at most): YARA crypto constants (findcrypt3), lief symbol /
import tables, embedded library version strings, Go import paths and JAR class paths.
Constants and version strings prove *presence*, not *use*; every finding is tagged best_effort."""
from __future__ import annotations

import re
import zipfile
from functools import lru_cache
from pathlib import Path

from ecdat import tools
from ecdat.collectors.base import Collector, Target, is_binary, path_context, rel, walk_files
from ecdat.knowledge import KnowledgeBase
from ecdat.model import RawFinding

# findcrypt3 rule-name prefix -> canonical algorithm (None = ignore: CRCs, bignum libs, TEA...)
YARA_MAP = {
    "RijnDael": "AES", "SHA256": "SHA-256", "SHA1": "SHA-1", "SHA512": "SHA-512", "MD5": "MD5", "DES": "DES",
    "FlyUtilsCnDES": "DES", "BLOWFISH": "Blowfish", "RsaRef2": "RSA", "RsaEuro": "RSA", "salsa20": "ChaCha20",
    "WHIRLPOOL": None, "RIPEMD160": None, "RC6": None, "TEA": None, "TEAN": None, "CRC32": None, "CRC32b": None,
    "CRC32c": None, "CRC16": None, "Sosemanuk": None, "WellRNG512": None, "Prime": None, "Big": None, "BigDig": None,
    "FGint": None, "Delphi": None, "DCP": None, "LockBox": None, "Miracl": None, "CryptoPP": None, "OpenSSL": None,
    "x509": None, "pkcs8": None, "Elf": None, "Unknown": None, "Crypt32": None, "VC6": None, "VC8": None, "DarkEYEv3": None,
}
YARA_LIB = {"OpenSSL": "openssl", "CryptoPP": "cryptopp", "Miracl": "miracl", "LockBox": "lockbox", "DCP": "dcpcrypt",
            "Crypt32": "windows-capi", "RsaRef2": "rsaref", "x509": "x509-certificate", "pkcs8": "pkcs8-private-key"}
VERSION_RES = [
    (re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)"), "openssl"), (re.compile(rb"LibreSSL (\d+\.\d+\.\d+)"), "libressl"),
    (re.compile(rb"BoringSSL"), "boringssl"), (re.compile(rb"mbed ?TLS (\d+\.\d+\.\d+)", re.I), "mbedtls"),
    (re.compile(rb"wolfSSL (\d+\.\d+\.\d+)"), "wolfssl"), (re.compile(rb"GnuTLS (\d+\.\d+\.\d+)"), "gnutls"),
    (re.compile(rb"libsodium (\d+\.\d+\.\d+)"), "libsodium"), (re.compile(rb"liboqs (\d+\.\d+\.\d+)"), "liboqs"),
    (re.compile(rb"Botan (\d+\.\d+\.\d+)"), "botan"), (re.compile(rb"NSS (\d+\.\d+)"), "nss"),
]
GO_PKGS = {
    b"crypto/rsa": ("RSA", "pke"), b"crypto/ecdsa": ("ECDSA", "signature"), b"crypto/ed25519": ("Ed25519", "signature"),
    b"crypto/ecdh": ("ECDH", "key-agree"), b"crypto/aes": ("AES", "block-cipher"), b"crypto/des": ("3DES", "block-cipher"),
    b"crypto/rc4": ("RC4", "stream-cipher"), b"crypto/md5": ("MD5", "hash"), b"crypto/sha1": ("SHA-1", "hash"),
    b"crypto/sha256": ("SHA-256", "hash"), b"crypto/sha512": ("SHA-512", "hash"), b"crypto/sha3": ("SHA3-256", "hash"),
    b"crypto/hmac": ("HMAC", "mac"), b"crypto/mlkem": ("ML-KEM-768", "kem"), b"crypto/dsa": ("DSA", "signature"),
    b"golang.org/x/crypto/chacha20poly1305": ("ChaCha20", "ae"), b"golang.org/x/crypto/curve25519": ("X25519", "key-agree"),
    b"golang.org/x/crypto/bcrypt": ("bcrypt", "kdf"), b"golang.org/x/crypto/scrypt": ("scrypt", "kdf"),
    b"golang.org/x/crypto/argon2": ("Argon2", "kdf"), b"golang.org/x/crypto/pbkdf2": ("PBKDF2", "kdf"),
    b"golang.org/x/crypto/blowfish": ("Blowfish", "block-cipher"), b"crypto/tls": ("TLS", "protocol"),
    b"golang.org/x/crypto/ssh": ("SSH", "protocol"),
}
SYMBOL_MAP = [
    (re.compile(r"^(RSA_|rsa_|EVP_PKEY_CTX_set_rsa|RSA_generate|RSAPublic|RSAPrivate)"), "RSA", "pke"),
    (re.compile(r"^(AES_|aes_|EVP_aes_|AesEncrypt|Rijndael|mbedtls_aes)"), "AES", "block-cipher"),
    (re.compile(r"^(SHA256_|sha256_|EVP_sha256|mbedtls_sha256|Sha256)"), "SHA-256", "hash"),
    (re.compile(r"^(SHA384_|EVP_sha384)"), "SHA-384", "hash"),
    (re.compile(r"^(SHA512_|EVP_sha512|mbedtls_sha512)"), "SHA-512", "hash"),
    (re.compile(r"^(SHA1_|sha1_|EVP_sha1|mbedtls_sha1|Sha1)"), "SHA-1", "hash"),
    (re.compile(r"^(MD5_|md5_|EVP_md5|mbedtls_md5|Md5)"), "MD5", "hash"),
    (re.compile(r"^(EC_KEY_|ECDSA_|ecdsa_|mbedtls_ecdsa)"), "ECDSA", "signature"),
    (re.compile(r"^(ECDH_|mbedtls_ecdh|X25519)"), "ECDH", "key-agree"),
    (re.compile(r"^(DH_|mbedtls_dhm)"), "DH", "key-agree"),
    (re.compile(r"^(DES_|des_|EVP_des)"), "DES", "block-cipher"),
    (re.compile(r"^(RC4_|rc4_|EVP_rc4)"), "RC4", "stream-cipher"),
    (re.compile(r"^(BF_|EVP_bf_)"), "Blowfish", "block-cipher"),
    (re.compile(r"^(ChaCha20|chacha20|EVP_chacha20|crypto_aead_chacha20)"), "ChaCha20", "ae"),
    (re.compile(r"^(crypto_box|crypto_scalarmult)"), "X25519", "key-agree"),
    (re.compile(r"^(crypto_sign|ED25519_|ed25519_)"), "Ed25519", "signature"),
    (re.compile(r"^(HMAC|hmac_|EVP_MAC)"), "HMAC", "mac"),
    (re.compile(r"^(PKCS5_PBKDF2_HMAC|pbkdf2)"), "PBKDF2", "kdf"),
    (re.compile(r"^(OQS_KEM_ml_kem|pqcrystals_kyber|mlkem)"), "ML-KEM-768", "kem"),
    (re.compile(r"^(OQS_SIG_ml_dsa|pqcrystals_dilithium|mldsa)"), "ML-DSA-65", "signature"),
]
LIB_SYMBOLS = [
    (re.compile(r"^(EVP_|SSL_|CRYPTO_|OPENSSL_|BIO_|X509_)"), "openssl"), (re.compile(r"^mbedtls_"), "mbedtls"),
    (re.compile(r"^wolfSSL_"), "wolfssl"), (re.compile(r"^(sodium_|crypto_(box|sign|secretbox|aead))"), "libsodium"),
    (re.compile(r"^(BCrypt|NCrypt)"), "windows-cng"), (re.compile(r"^Crypt(Encrypt|Decrypt|GenKey|AcquireContext|HashData|CreateHash)"), "windows-capi"),
    (re.compile(r"^gnutls_"), "gnutls"), (re.compile(r"^OQS_"), "liboqs"), (re.compile(r"^(CC(Crypt|Digest|Hmac)|SecKey)"), "apple-commoncrypto"),
]
JAR_PATHS = {"javax/crypto/": "jce", "java/security/": "jca", "org/bouncycastle/": "bouncycastle", "io/jsonwebtoken/": "jjwt",
             "org/apache/sshd/": "apache-sshd", "com/jcraft/jsch/": "jsch"}


@lru_cache(maxsize=1)
def _yara_rules():
    try:
        import yara
    except ImportError:
        return None
    if not tools.FINDCRYPT_RULES.exists():
        return None
    try:
        return yara.compile(filepath=str(tools.FINDCRYPT_RULES))
    except Exception:
        return None


def _strings(data: bytes, minlen: int = 6):
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        yield m.group(0)


class BinaryCollector(Collector):
    name = "binary"
    kinds = {"dir", "repo", "image", "binary"}

    def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]:
        root = Path(target.path)
        out: list[RawFinding] = []
        for path in walk_files(root, max_size=200 * 1024 * 1024):
            if not is_binary(path):
                continue
            location = rel(path, root) if root.is_dir() else path.name
            if target.props.get("location_prefix"):
                location = target.props["location_prefix"] + location
            ctx = path_context(location)
            ctx.update({"zone": target.zone, "best_effort": True})
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if path.suffix.lower() in (".jar", ".war", ".ear", ".zip", ".aar"):
                out += self._jar(path, location, target, ctx)
                continue
            seen: set = set()

            def add(name, method, extra: dict, conf="medium", asset_type="algorithm", snippet=""):
                key = (asset_type, name, method)
                if key in seen:
                    return
                seen.add(key)
                props = {"api": "binary", "method": method, **extra}
                out.append(RawFinding("binary", asset_type, name, location, None, snippet[:200], conf, target.name, props, dict(ctx)))

            # 1) YARA crypto constants
            rules = _yara_rules()
            if rules is not None:
                try:
                    for m in rules.match(data=data, timeout=60):
                        prefix = m.rule.split("_")[0]
                        alg = YARA_MAP.get(prefix, None)
                        if alg:
                            add(alg, "yara-constant", {"rule": m.rule, "primitive": kb.info(alg).get("primitive")}, snippet=f"yara:{m.rule}")
                        elif prefix in YARA_LIB:
                            add(YARA_LIB[prefix], "yara-signature", {"rule": m.rule, "ecosystem": "system", "provides": []},
                                conf="low", asset_type="library", snippet=f"yara:{m.rule}")
                except Exception:
                    pass
            # 2) version strings + Go import paths + notable strings
            for s in _strings(data):
                for rx, lib in VERSION_RES:
                    mm = rx.search(s)
                    if mm:
                        ver = mm.group(1).decode() if mm.groups() else None
                        sig = (kb.libraries.get("system") or {}).get(lib, {})
                        add(lib, "version-string", {"version": ver, "ecosystem": "system", "provides": list(sig.get("provides", [])),
                                                    "pqc_native_from": sig.get("pqc_native_from"), "pqc_native": bool(sig.get("pqc_native"))},
                            conf="medium", asset_type="library", snippet=s.decode("ascii", "replace"))
                for pkg, (alg, prim) in GO_PKGS.items():
                    if pkg in s and (s.startswith(pkg) or b"/" + pkg in s or s.startswith(b"vendor/" + pkg)):
                        if prim == "protocol":
                            add(alg, "go-import", {"type": alg.lower(), "language": "go"}, asset_type="protocol", snippet=s.decode("ascii", "replace"))
                        else:
                            add(alg, "go-import", {"primitive": prim, "language": "go"}, snippet=s.decode("ascii", "replace"))
            # 3) symbols / imports via lief
            for sym in self._symbols(path):
                for rx, alg, prim in SYMBOL_MAP:
                    if rx.match(sym):
                        add(alg, "symbol", {"symbol": sym, "primitive": prim}, snippet=sym)
                        break
                for rx, lib in LIB_SYMBOLS:
                    if rx.match(sym):
                        sig = (kb.libraries.get("system") or {}).get(lib, {})
                        add(lib, "symbol", {"ecosystem": "system", "provides": list(sig.get("provides", [])), "symbol": sym},
                            conf="medium", asset_type="library", snippet=sym)
                        break
        return out

    @staticmethod
    def _symbols(path: Path) -> list[str]:
        try:
            import lief
        except ImportError:
            return []
        try:
            lief.logging.disable()
            b = lief.parse(str(path))
        except Exception:
            return []
        if b is None:
            return []
        names: list[str] = []
        try:
            for s in getattr(b, "imported_functions", []) or []:
                names.append(str(getattr(s, "name", s)))
            for s in getattr(b, "exported_functions", []) or []:
                names.append(str(getattr(s, "name", s)))
            for s in getattr(b, "symbols", []) or []:
                n = getattr(s, "name", None)
                if n:
                    names.append(str(n))
            for s in getattr(b, "dynamic_symbols", []) or []:
                n = getattr(s, "name", None)
                if n:
                    names.append(str(n))
        except Exception:
            pass
        return list(dict.fromkeys(names))[:20000]

    def _jar(self, path: Path, location: str, target: Target, ctx: dict) -> list[RawFinding]:
        out = []
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
        except Exception:
            return out
        hit: dict[str, int] = {}
        for n in names:
            for prefix, lib in JAR_PATHS.items():
                if n.startswith(prefix):
                    hit[lib] = hit.get(lib, 0) + 1
        for lib, count in hit.items():
            out.append(RawFinding("binary", "library", lib, location, None, f"{count} classes under {lib}", "medium", target.name,
                                  {"api": "binary", "method": "jar-classpath", "ecosystem": "maven", "provides": [], "class_count": count}, dict(ctx)))
        return out
