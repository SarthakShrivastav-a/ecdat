"""Patch *suggestions* (unified diff text) for a handful of common patterns. Never applied automatically:
LLM-generated PQC code drifts insecure (arXiv:2606.19474), so we show the evidence and let a human decide."""
from __future__ import annotations

import re

from ecdat.model import CryptoAsset


def _diff(file: str, line: int | None, old: str, new_lines: list[str]) -> str:
    ln = line or 1
    body = [f"--- a/{file}", f"+++ b/{file}", f"@@ -{ln},1 +{ln},{len(new_lines)} @@", f"-{old}"] + [f"+{l}" for l in new_lines]
    return "\n".join(body) + "\n"


def _patch(title: str, file: str, line: int | None, old: str, new: list[str], note: str) -> dict:
    return {"title": title, "file": file, "line": line, "unified_diff": _diff(file, line, old, new), "note": note}


def suggest(asset: CryptoAsset) -> list[dict]:
    out: list[dict] = []
    for e in asset.evidence:
        s = (e.snippet or "").strip()
        f = e.location
        if not s:
            continue
        indent = ""
        # python: pyca RSA keygen -> ML-KEM-768 (kyber-py), keep X25519 alongside for hybrid
        if "rsa.generate_private_key" in s:
            m = re.match(r"^(\s*)(?:(\w+)\s*=\s*)?", s)
            var = (m.group(2) if m and m.group(2) else "key")
            out.append(_patch("RSA keygen -> ML-KEM-768 (FIPS 203) via kyber-py", f, e.line, s,
                              ["from kyber_py.ml_kem import ML_KEM_768  # pip install kyber-py",
                               f"{var}_ek, {var}_dk = ML_KEM_768.keygen()  # encapsulation/decapsulation keys",
                               "# hybrid: keep an X25519 share alongside during transition (X25519MLKEM768)"],
                              "RSA encryption becomes KEM + AES-256-GCM (KEM-DEM); callers of encrypt()/decrypt() change shape."))
        elif "KeyPairGenerator.getInstance(\"RSA\")" in s or "KeyPairGenerator.getInstance(\"EC\")" in s:
            out.append(_patch("KeyPairGenerator RSA/EC -> ML-KEM (JDK 24, JEP 496)", f, e.line, s,
                              [s.replace('getInstance("RSA")', 'getInstance("ML-KEM")').replace('getInstance("EC")', 'getInstance("ML-KEM")'),
                               "// kpg.initialize(NamedParameterSpec.ML_KEM_768);  // JDK 24+"],
                              "Requires JDK 24+ (or Bouncy Castle 1.79+). Signing keys should move to ML-DSA instead."))
        elif "Signature.getInstance(" in s and re.search(r"with(ECDSA|RSA|DSA)", s):
            out.append(_patch("Signature ECDSA/RSA -> ML-DSA-65 (JDK 24, JEP 497)", f, e.line, s,
                              [re.sub(r'"[^"]*with(?:ECDSA|RSA|DSA)"', '"ML-DSA-65"', s)],
                              "Signatures grow to 3,309 bytes; verify wire formats and certificate profiles first."))
        elif "rsa.GenerateKey(" in s:
            out.append(_patch("crypto/rsa -> crypto/mlkem (Go 1.24)", f, e.line, s,
                              ['dk, err := mlkem.GenerateKey768() // import "crypto/mlkem"',
                               "// ek := dk.EncapsulationKey(); ss, ct := ek.Encapsulate()"],
                              "Go 1.24+ ships ML-KEM natively; TLS already prefers X25519MLKEM768 when CurvePreferences is nil."))
        elif "ssl_ecdh_curve" in s:
            out.append(_patch("nginx: enable hybrid PQ key exchange", f, e.line, s,
                              ["ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;"],
                              "Needs nginx built against OpenSSL >= 3.5. Clients without PQ support fall back to X25519."))
        elif "ssl_protocols" in s and re.search(r"TLSv1(\.0|\.1)?\b(?!\.[23])", s):
            out.append(_patch("nginx: drop legacy TLS versions", f, e.line, s, ["ssl_protocols TLSv1.2 TLSv1.3;"],
                              "Removes SSLv3/TLS 1.0/1.1; check client compatibility."))
        elif re.search(r"hashlib\.(md5|sha1)\(", s) and asset.context.get("usage") == "security":
            out.append(_patch("hashlib md5/sha1 -> sha256 (classical hygiene)", f, e.line, s,
                              [re.sub(r"hashlib\.(md5|sha1)\(", "hashlib.sha256(", s)],
                              "Not a PQC change; MD5/SHA-1 are broken classically. Password hashing should use Argon2/bcrypt, not a plain hash."))
        elif "MessageDigest.getInstance(\"MD5\")" in s or "MessageDigest.getInstance(\"SHA-1\")" in s or "MessageDigest.getInstance(\"SHA1\")" in s:
            out.append(_patch("MessageDigest MD5/SHA-1 -> SHA-256", f, e.line, s,
                              [re.sub(r'"(MD5|SHA-?1)"', '"SHA-256"', s)], "Classical hygiene, not PQC."))
        elif "DESede" in s or "TripleDES" in s or 'getInstance("DES' in s:
            out.append(_patch("3DES/DES -> AES/GCM/NoPadding", f, e.line, s,
                              [re.sub(r'"(DESede|DES)/[^"]*"', '"AES/GCM/NoPadding"', s)],
                              "64-bit block ciphers (Sweet32) are disallowed; AES-256-GCM is the drop-in AEAD."))
        elif "createCipheriv('aes-128" in s or 'createCipheriv("aes-128' in s:
            out.append(_patch("aes-128 -> aes-256-gcm", f, e.line, s,
                              [re.sub(r"aes-128-[a-z]+", "aes-256-gcm", s)], "Key length must become 32 bytes."))
    return out


def apply(assets: list[CryptoAsset]) -> None:
    for a in assets:
        if a.risk and a.risk.tier == "SAFE":
            continue
        ps = suggest(a)
        if a.recommendation is not None:
            a.recommendation.patches = ps
        else:
            a.context["patches"] = ps
