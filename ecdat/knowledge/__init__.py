"""KnowledgeBase: all crypto knowledge is YAML data, loaded once. Adding an algorithm is a data edit."""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

HERE = Path(__file__).parent
SCHEMAS = HERE.parent / "schemas"


def _load(name: str) -> dict:
    p = HERE / name
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}


class KnowledgeBase:
    def __init__(self):
        self.algorithms: dict = _load("algorithms.yaml")
        self.libraries: dict = _load("library_signatures.yaml")
        self.source_patterns: dict = _load("source_patterns.yaml")
        self.pqc: dict = _load("pqc_mappings.yaml")
        self.data_classes: dict = _load("data_classes.yaml")
        self.frameworks: dict = _load("frameworks.yaml")
        defs = json.loads((SCHEMAS / "cryptography-defs.json").read_text(encoding="utf-8"))
        self.registry_families: set[str] = {a["family"] for a in defs["algorithms"]}
        self.registry: dict = {a["family"]: a for a in defs["algorithms"]}
        self.curves: dict = {}
        for grp in defs["ellipticCurves"]:
            for c in grp["curves"]:
                self.curves[c["name"].lower()] = {**c, "group": grp["name"]}
        self._alias: dict[str, str] = {}
        for canon, info in self.algorithms.items():
            self._alias[canon.lower()] = canon
            for a in info.get("aliases", []) or []:
                self._alias[str(a).lower()] = canon
        self._sized_re = re.compile(r"^(aes|sha|rsa|ecdsa|ecdh|dh|dsa|camellia|aria)[-_ ]?(\d{2,4})")

    # ---- names ---------------------------------------------------------------------------
    def canonicalise(self, name: str | None, key_size: int | None = None) -> str | None:
        if not name:
            return None
        n = str(name).strip().lower()
        canon = self._alias.get(n)
        if canon is None:
            head = re.split(r"[/\-_ ]", n)[0]
            canon = self._alias.get(head)
            if canon is None:
                m = self._sized_re.match(n)
                if m:
                    canon = self._alias.get(m.group(1))
                    key_size = key_size or int(m.group(2))
        if canon is None:
            return None
        sized = self.algorithms[canon].get("sized_variants") or {}
        if key_size and str(key_size) in sized:
            return sized[str(key_size)]
        # "aes-256-gcm" -> alias hit on "aes-256-gcm" may already be AES-256
        return canon

    def info(self, canonical: str) -> dict:
        return self.algorithms.get(canonical, {})

    def family(self, canonical: str) -> str:
        return self.info(canonical).get("family", canonical)

    def curve(self, name: str | None) -> dict | None:
        if not name:
            return None
        n = name.lower().replace("_", "-")
        aliases = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p256": "secp256r1", "nistp256": "secp256r1",
                   "p-384": "secp384r1", "p384": "secp384r1", "nistp384": "secp384r1", "p-521": "secp521r1",
                   "p521": "secp521r1", "nistp521": "secp521r1", "x25519": "curve25519", "ed25519": "ed25519"}
        n = aliases.get(n, n)
        return self.curves.get(n)

    def security_bits(self, canonical: str, key_size: int | None) -> int | None:
        bits = self.info(canonical).get("classical_security_bits")
        if isinstance(bits, dict):
            if key_size is None:
                return None
            best = None
            for k, v in sorted(((int(k), v) for k, v in bits.items())):
                if key_size >= k:
                    best = v
            return best
        return bits

    def is_pqc(self, canonical: str) -> bool:
        return bool(self.info(canonical).get("pqc"))
