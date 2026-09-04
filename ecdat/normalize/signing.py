"""Sign the CBOM with ML-DSA-65 (FIPS 204) via the pure-Python dilithium-py implementation. Detached signature:
<bom>.mldsa65.sig (base64) + ecdat-mldsa65.pub. JSF cannot express ML-DSA yet, hence detached."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from dilithium_py.ml_dsa import ML_DSA_65

ALG = "ML-DSA-65"


def keygen() -> tuple[bytes, bytes]:
    return ML_DSA_65.keygen()


def sign(data: bytes, sk: bytes) -> bytes:
    return ML_DSA_65.sign(sk, data)


def verify(data: bytes, sig: bytes, pk: bytes) -> bool:
    try:
        return bool(ML_DSA_65.verify(pk, data, sig))
    except Exception:
        return False


def load_or_create_keys(key_dir: Path) -> tuple[bytes, bytes]:
    key_dir.mkdir(parents=True, exist_ok=True)
    pk_path, sk_path = key_dir / "ecdat-mldsa65.pub", key_dir / "ecdat-mldsa65.key"
    if pk_path.exists() and sk_path.exists():
        return base64.b64decode(pk_path.read_text()), base64.b64decode(sk_path.read_text())
    pk, sk = keygen()
    pk_path.write_text(base64.b64encode(pk).decode())
    sk_path.write_text(base64.b64encode(sk).decode())
    return pk, sk


def sign_file(bom_path: Path, key_dir: Path) -> Path:
    pk, sk = load_or_create_keys(key_dir)
    data = bom_path.read_bytes()
    sig = sign(data, sk)
    out = bom_path.with_name(bom_path.name + ".mldsa65.sig")
    out.write_text(json.dumps({"algorithm": ALG, "standard": "FIPS 204", "signed_file": bom_path.name,
                               "sha256": hashlib.sha256(data).hexdigest(), "signature_b64": base64.b64encode(sig).decode(),
                               "public_key_b64": base64.b64encode(pk).decode()}, indent=2))
    (bom_path.parent / "ecdat-mldsa65.pub").write_text(base64.b64encode(pk).decode())
    return out


def verify_file(bom_path: Path, sig_path: Path | None = None) -> bool:
    sig_path = sig_path or bom_path.with_name(bom_path.name + ".mldsa65.sig")
    meta = json.loads(sig_path.read_text())
    data = bom_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != meta["sha256"]:
        return False
    return verify(data, base64.b64decode(meta["signature_b64"]), base64.b64decode(meta["public_key_b64"]))
