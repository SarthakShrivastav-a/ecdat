# ECDAT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working, end-to-end Cryptographic Bill of Materials analytics tool for SIH 2026 PS 26164: scan source, dependencies, certificates/keys, binaries, container images, live TLS/SSH endpoints and pcaps; reconcile into one signed CycloneDX 1.7 CBOM; score quantum risk (HNDL-aware Mosca, agility, tiers, DST/CERT-In/NIST overlays); produce a budgeted migration plan, VEX, patches, reports; serve an interactive dashboard; gate CI.

**Architecture:** Seven one-directional layers (targets → collectors → CBOM → enrichment → risk → plan → surfaces). Collectors are plugins implementing one `Collector` protocol and emit `RawFinding`s; `merge` turns them into `CryptoAsset`s; every later layer reads only assets. All crypto knowledge lives in YAML under `ecdat/knowledge/`. External engines (OpenGrep, cbomkit-theia, Syft, tshark, crane) are optional accelerators discovered on PATH or in `tools/`; every collector has a pure-Python path so the whole pipeline runs offline on this Windows machine.

**Tech Stack:** Python 3.11 venv at `demo/ecdat/.venv` (cryptography, cyclonedx-python-lib 11.12, tree-sitter 0.25 + py/js/java/go/c grammars, yara-python + findcrypt3 rules, lief, scapy, cryptolyzer, dilithium-py, fastapi/uvicorn, typer, jsonschema, reportlab, pytest); tools/ (opengrep 1.29, syft 1.51, findcrypt3.rules, semgrep-crypto-rules/); Go-built `cbomkit-theia.exe` and `crane.exe` in `%USERPROFILE%\go\bin`; tshark 4.6.8; React + Vite + TypeScript dashboard in `web/`.

**Spec:** `C:\customize\SIH2026\ecdat\00_SOLUTION_END_TO_END.md` (sections 4–8 are the architecture, scoring, honesty rules, evaluation and demo this plan implements). Research digests in `C:\customize\SIH2026\ecdat\research\`.

## Global Constraints

- Python 3.11, run everything with `demo/ecdat/.venv/Scripts/python.exe`; never touch the internship repo's venv.
- CBOM output MUST be CycloneDX **1.7** JSON and MUST validate against `ecdat/schemas/bom-1.7.schema.json`.
- Canonical algorithm names MUST come from `ecdat/schemas/cryptography-defs.json` families where one exists.
- Every `RawFinding` and `CryptoAsset` carries `confidence` ∈ {high, medium, low} and at least one `Evidence`.
- Mosca (`X + Y > Z`) is applied ONLY to confidentiality primitives (pke, kem, key-agree, block-cipher, stream-cipher, ae); signatures/hashes/MACs get deadline-driven scoring.
- Z (years until a CRQC) is a parameter with presets `{aggressive: 2032, nist: 2035, gri: 2041}`; never a constant in code.
- Binary findings are `medium` confidence at most and labelled `best-effort` in reports.
- No network access required for any test; live-TLS tests use a local server; container tests use a synthetic OCI tar.
- Knowledge (algorithms, library signatures, PQC mappings, data classes, frameworks, source patterns) lives in YAML, never hardcoded in Python.
- Patches are suggestions (unified diff text) and are never applied automatically.
- No git repository exists at `C:\customize\SIH2026`; "Commit" steps are replaced by "Checkpoint: run full test suite" (a `git init` inside `demo/ecdat` is done in Task 1 so later work can be committed locally).

---

## File Structure

```
demo/ecdat/
  pyproject.toml                      package metadata, deps, pytest config, console script `ecdat`
  README.md                           install (online + air-gapped), usage, demo script
  ecdat/__init__.py                   __version__
  ecdat/model.py                      Evidence, RawFinding, Component, CryptoAsset, ScanResult, ScanParams (dataclasses + to_dict)
  ecdat/knowledge/__init__.py         KnowledgeBase: loads all YAML, canonicalise(name), lookup(name), registry families
  ecdat/knowledge/algorithms.yaml     canonical algorithms, aliases, primitive, OID, quantum class, security bits, replacements
  ecdat/knowledge/library_signatures.yaml  package → algorithms it provides, per ecosystem
  ecdat/knowledge/source_patterns.yaml     per-language call/import patterns → algorithm, primitive, arg extraction
  ecdat/knowledge/pqc_mappings.yaml   replacement targets with FIPS refs, size/latency deltas, runtime availability
  ecdat/knowledge/data_classes.yaml   data class → lifetime years + path/identifier hints
  ecdat/knowledge/frameworks.yaml     DST M1/M2/M3, CERT-In, NIST IR 8547, CNSA 2.0, EU, UK deadlines and rules
  ecdat/schemas/                      vendored bom-1.7 + spdx + jsf schemas, cryptography-defs.json
  ecdat/tools.py                      locate external binaries (opengrep, theia, syft, tshark, crane); versions
  ecdat/collectors/base.py            Collector protocol, Target, helpers (walk_files, is_binary, read_text)
  ecdat/collectors/source.py          tree-sitter engine (+ regex fallback) driven by source_patterns.yaml
  ecdat/collectors/opengrep.py        OpenGrep engine → RawFindings (optional)
  ecdat/collectors/dependency.py      manifests + lockfiles → library findings; Syft optional
  ecdat/collectors/certificate.py     PEM/DER/PKCS#12/JKS certs & keys; theia optional enrichment
  ecdat/collectors/binary.py          yara findcrypt + lief symbols/imports + version strings
  ecdat/collectors/container.py       docker/OCI tar → rootfs → re-run file collectors; theia image optional
  ecdat/collectors/protocol.py        live TLS (cryptolyzer, ssl fallback) + SSH KEX banner
  ecdat/collectors/pcap.py            scapy TLS ClientHello/ServerHello + cert extraction; tshark optional
  ecdat/collectors/__init__.py        REGISTRY = {name: class}; run_collectors(targets, kb) → list[RawFinding]
  ecdat/normalize/merge.py            RawFinding[] → CryptoAsset[] (dedupe, evidence merge, corroboration)
  ecdat/normalize/cyclonedx.py        assets → CycloneDX 1.7 dict; validate(); write()
  ecdat/normalize/signing.py          ML-DSA-65 keygen/sign/verify of BOM bytes (detached)
  ecdat/normalize/certin.py           CERT-In v2.0 Table 9 completeness per asset type
  ecdat/enrich/context.py             test/vendored/comment/non-security classification
  ecdat/enrich/exposure.py            internal/external, in-transit/at-rest/signing-only
  ecdat/enrich/lifetime.py            data class inference → X years; criticality → QRAMM multiplier
  ecdat/enrich/agility.py             seven-dimension agility score → Y years
  ecdat/risk/quantum.py               quantum class + HNDL applicability
  ecdat/risk/mosca.py                 X+Y>Z, tiers, priority score
  ecdat/risk/frameworks.py            overlays: DST, NIST IR 8547, CNSA 2.0, CERT-In
  ecdat/plan/pqc.py                   recommendations with deltas
  ecdat/plan/optimizer.py             greedy knapsack under engineer budget
  ecdat/plan/vex.py                   VEX (CycloneDX vulnerabilities + analysis state)
  ecdat/plan/patches.py               unified-diff suggestions for known patterns
  ecdat/export/sarif.py, csv_export.py, html_report.py, pdf_report.py
  ecdat/pipeline.py                   run(config) → ScanResult; recompute(result, params)
  ecdat/config.py                     YAML config → ScanConfig(targets, params)
  ecdat/gate.py                       CI gate: baseline vs current → exit code + summary
  ecdat/eval.py                       precision/recall vs zoo truth
  ecdat/api/server.py                 FastAPI: scan, results, recompute, plan, exports; serves web/dist
  ecdat/cli.py                        typer: scan, report, serve, gate, zoo, eval
  scripts/build_zoo.py                generates certs, keystore, Go binary, OCI tar, pcap, truth file
  tests/fixtures/zoo/                 planted multi-language corpus (source files committed; artefacts built)
  tests/test_*.py                     one per module
  web/                                Vite + React + TS dashboard
  .github/workflows/ecdat-gate.yml    GitHub Action for the CI gate
```

---

### Task 1: Skeleton, data model, knowledge base

**Files:**
- Create: `pyproject.toml`, `ecdat/__init__.py`, `ecdat/model.py`, `ecdat/knowledge/__init__.py`, `ecdat/knowledge/algorithms.yaml`, `ecdat/tools.py`
- Test: `tests/test_model.py`, `tests/test_knowledge.py`

**Interfaces:**
- Produces: `Evidence(collector, location, line, snippet, confidence, context)`, `RawFinding(collector, asset_type, name, location, line, snippet, confidence, component, props, context)`, `Component(bom_ref, name, type, version, zone, data_class, criticality, path)`, `CryptoAsset(bom_ref, asset_type, name, family, primitive, key_size, mode, padding, oid, parameter_set, crypto_functions, classical_security_level, nist_quantum_security_level, component, provided_by, evidence, props, context, exposure, lifetime_years, criticality, agility, risk, recommendation, vex)`, `ScanParams(z_year=2041, y_default=3.0, engineers=4, months=6, profile='cii', now_year=2026)`, `ScanResult(targets, components, assets, params, stats, tool_versions, timestamp)`; all have `to_dict()`.
- `KnowledgeBase()` with `.algorithms: dict`, `.canonicalise(name:str, key_size:int|None=None) -> str|None`, `.info(canonical:str) -> dict`, `.family(canonical) -> str`, `.registry_families: set[str]`.
- `ecdat.tools.find(name) -> Path|None`, `ecdat.tools.versions() -> dict`.

- [ ] **Step 1: Write pyproject.toml**

```toml
[project]
name = "ecdat"
version = "0.1.0"
description = "Enterprise Cryptographic Discovery & Analysis Tool - CBOM analytics + quantum risk"
requires-python = ">=3.11"
dependencies = ["cryptography","cyclonedx-python-lib>=11.11","lief","scapy","tree-sitter>=0.25",
 "tree-sitter-python","tree-sitter-javascript","tree-sitter-java","tree-sitter-go","tree-sitter-c",
 "yara-python","fastapi","uvicorn[standard]","pyyaml","typer","rich","jsonschema","reportlab",
 "dilithium-py","kyber-py","httpx","python-multipart","cryptolyzer","pyjks","pycryptodomex"]
[project.scripts]
ecdat = "ecdat.cli:app"
[tool.pytest.ini_options]
testpaths = ["tests"]
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
[tool.setuptools.packages.find]
include = ["ecdat*"]
[tool.setuptools.package-data]
ecdat = ["knowledge/*.yaml","schemas/*.json"]
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_model.py
from ecdat.model import RawFinding, CryptoAsset, Evidence, ScanParams
def test_rawfinding_roundtrip():
    f = RawFinding(collector="source", asset_type="algorithm", name="RSA", location="a.py", line=3,
                   snippet="rsa.generate_private_key(key_size=2048)", confidence="high",
                   component="app", props={"key_size": 2048}, context={"is_test": False})
    d = f.to_dict(); assert d["props"]["key_size"] == 2048 and d["confidence"] == "high"
def test_scanparams_defaults():
    p = ScanParams(); assert p.z_year == 2041 and p.engineers == 4

# tests/test_knowledge.py
from ecdat.knowledge import KnowledgeBase
kb = KnowledgeBase()
def test_canonicalise_aliases():
    assert kb.canonicalise("rsaEncryption") == "RSA"
    assert kb.canonicalise("sha256WithRSAEncryption") == "RSA"
    assert kb.canonicalise("aes", 256) == "AES-256"
    assert kb.canonicalise("AES/CBC/PKCS5Padding") == "AES"
    assert kb.canonicalise("md5") == "MD5"
    assert kb.canonicalise("nonsense-xyz") is None
def test_info_has_quantum_class():
    assert kb.info("RSA")["quantum"] == "broken"
    assert kb.info("AES-256")["quantum"] == "safe"
    assert kb.info("MD5")["quantum"] == "legacy-broken"
def test_registry_families_loaded():
    assert "RSASSA-PKCS1" in kb.registry_families and "ML-KEM" in kb.registry_families
```

- [ ] **Step 3: Run to verify failure**: `.venv/Scripts/python.exe -m pytest tests/test_model.py tests/test_knowledge.py -q` → ImportError.

- [ ] **Step 4: Implement `ecdat/model.py`** (dataclasses with `to_dict()` via `dataclasses.asdict`, nested objects handled), `ecdat/knowledge/__init__.py`:

```python
import re, json, yaml
from pathlib import Path
HERE = Path(__file__).parent
class KnowledgeBase:
    def __init__(self):
        self.algorithms = yaml.safe_load((HERE/"algorithms.yaml").read_text(encoding="utf-8"))
        self.libraries = yaml.safe_load((HERE/"library_signatures.yaml").read_text(encoding="utf-8")) if (HERE/"library_signatures.yaml").exists() else {}
        self.source_patterns = yaml.safe_load((HERE/"source_patterns.yaml").read_text(encoding="utf-8")) if (HERE/"source_patterns.yaml").exists() else {}
        self.pqc = yaml.safe_load((HERE/"pqc_mappings.yaml").read_text(encoding="utf-8")) if (HERE/"pqc_mappings.yaml").exists() else {}
        self.data_classes = yaml.safe_load((HERE/"data_classes.yaml").read_text(encoding="utf-8")) if (HERE/"data_classes.yaml").exists() else {}
        self.frameworks = yaml.safe_load((HERE/"frameworks.yaml").read_text(encoding="utf-8")) if (HERE/"frameworks.yaml").exists() else {}
        defs = json.loads((HERE.parent/"schemas"/"cryptography-defs.json").read_text(encoding="utf-8"))
        self.registry_families = {a["family"] for a in defs["algorithms"]}
        self.curves = {c["name"].lower(): c for grp in defs["ellipticCurves"] for c in grp["curves"]}
        self._alias = {}
        for canon, info in self.algorithms.items():
            self._alias[canon.lower()] = canon
            for a in info.get("aliases", []): self._alias[a.lower()] = canon
    def canonicalise(self, name, key_size=None):
        if not name: return None
        n = name.strip().lower()
        if n in self._alias: canon = self._alias[n]
        else:
            head = re.split(r"[/\-_ ]", n)[0]          # "aes/cbc/pkcs5padding" -> "aes"
            canon = self._alias.get(head)
            if canon is None:
                m = re.match(r"^(aes|sha|rsa|ecdsa|ecdh|dh|dsa)[-_ ]?(\d+)", n)
                if m: canon = self._alias.get(m.group(1)); key_size = key_size or int(m.group(2))
        if canon is None: return None
        sized = self.algorithms[canon].get("sized_variants", {})
        if key_size and str(key_size) in sized: return sized[str(key_size)]
        return canon
    def info(self, canonical): return self.algorithms[canonical]
    def family(self, canonical): return self.algorithms[canonical].get("family", canonical)
```

`algorithms.yaml` entries (write all of these): RSA (aliases rsa, rsaEncryption, rsassa-pss, rsa-oaep, rsa-pkcs1, sha256WithRSAEncryption, sha1WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption, RSA-2048, RSA-3072, RSA-4096; family RSASSA-PKCS1; primitive pke; oid 1.2.840.113549.1.1.1; quantum broken; reason Shor; security_bits {1024:80,2048:112,3072:128,4096:152}; legacy_min_key 2048; replace {kem: X25519MLKEM768, signature: ML-DSA-65}), ECDSA (ecdsa, ecdsa-with-SHA256, ecdsa-with-SHA384, id-ecPublicKey, EC, secp256r1, prime256v1, P-256, P-384; family ECDSA; primitive signature; quantum broken; replace ML-DSA-65), ECDH (ecdh, ecdhe, ECDHE-RSA, ECDHE-ECDSA; family ECDH; primitive key-agree; broken; replace X25519MLKEM768), X25519 (x25519, curve25519; key-agree; broken; replace X25519MLKEM768), Ed25519 (ed25519, eddsa; signature; broken; replace ML-DSA-65), DH (dh, dhe, diffie-hellman, ffdhe2048; key-agree; broken), DSA (dsa; signature; broken), AES (aes, AES/CBC/PKCS5Padding-ish via head split; family AES; primitive block-cipher; sized_variants {128: AES-128, 192: AES-192, 256: AES-256}; quantum weakened; replace AES-256), AES-128 (aes-128, aes128, aes-128-gcm, aes-128-cbc; weakened; security 128 classical, Grover ~64; replace AES-256), AES-192, AES-256 (aes-256, aes256, aes-256-gcm, aes-256-cbc; safe), ChaCha20 (chacha20, chacha20-poly1305; ae; safe), 3DES (3des, des3, desede, tripledes, des-ede3-cbc; legacy-broken), DES (des; legacy-broken), RC4 (rc4, arcfour; legacy-broken), Blowfish (blowfish, bf; legacy-broken), MD5 (md5; hash; legacy-broken), SHA-1 (sha1, sha-1; hash; legacy-broken), SHA-256 (sha256, sha-256, sha2-256; hash; safe), SHA-384, SHA-512, SHA3-256, SHA3-512, HMAC (hmac; mac; safe), PBKDF2 (pbkdf2, pbkdf2-hmac; kdf; safe), bcrypt, scrypt, Argon2 (kdf; safe), ML-KEM-768 (kyber, kyber768, ml-kem, mlkem768; kem; safe; family ML-KEM), ML-KEM-1024, ML-DSA-65 (dilithium, dilithium3, ml-dsa; signature; safe; family ML-DSA), ML-DSA-87, SLH-DSA (sphincs+; signature; safe), FN-DSA (falcon; signature; safe), HQC (kem; safe), X25519MLKEM768 (x25519mlkem768, x25519kyber768; combiner; safe; hybrid), TLS (protocol placeholder), SSH, IPsec/IKEv2. Each entry: `primitive`, `family`, `oid` where known, `quantum` ∈ {broken, weakened, legacy-broken, safe}, `quantum_reason`, `classical_security_bits` (int or map by key size), `nist_quantum_level` (0 for broken; 1/3/5 for PQC), `replace` map, `cert_in_name` example.

`ecdat/tools.py`: `find(name)` checks `tools/`, `%USERPROFILE%\go\bin`, `C:\Program Files\Wireshark`, then `shutil.which`.

- [ ] **Step 5: Run tests** → PASS. `git init` in `demo/ecdat`, add `.gitignore` (.venv, web/node_modules, web/dist, out/, *.pyc, tools/*.zip, tools/*.exe), commit "feat: skeleton, model, knowledge base".

---

### Task 2: Source collector (tree-sitter engine)

**Files:** Create `ecdat/collectors/base.py`, `ecdat/collectors/source.py`, `ecdat/knowledge/source_patterns.yaml`, `tests/fixtures/zoo/src/` (python/payments/auth.py, python/utils/cache.py, python/tests/test_auth.py, java/PaymentCrypto.java, go/main.go, js/server.js, c/legacy.c, nginx/nginx.conf, openssl.cnf), `tests/test_source.py`.

**Interfaces:**
- `Target(kind: 'dir'|'repo'|'image'|'certs'|'endpoints'|'pcap', path: str, name: str, zone: 'internal'|'external', data_class: str|None, criticality: str|None)`.
- `class Collector: name: str; kinds: set[str]; def collect(self, target: Target, kb: KnowledgeBase) -> list[RawFinding]`.
- `base.walk_files(root, exts=None, skip_dirs={'.git','node_modules','.venv','venv','dist','build','__pycache__'}) -> Iterator[Path]`.
- `SourceCollector().collect(target, kb)` finds algorithm findings with `props`: `{key_size, mode, padding, function, api, language, arg_literal}` and `context`: `{is_test, is_vendored, in_comment, line_text}`.

- [ ] **Step 1: Write fixture sources** (planted, with known truth). Example `python/payments/auth.py`:

```python
"""Payment service auth - planted crypto zoo (truth: RSA-2048 keygen, RSA-OAEP encrypt, ECDSA P-256 sign, AES-256-GCM, SHA-256, hardcoded)"""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
def make_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def encrypt_card(pubkey, pan: bytes) -> bytes:
    return pubkey.encrypt(pan, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
def sign_receipt(data: bytes) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(data, ec.ECDSA(hashes.SHA256()))
def seal(record: bytes) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    return AESGCM(key).encrypt(os.urandom(12), record, None)
```
`python/utils/cache.py` (truth: MD5 non-security use): `import hashlib; def cache_key(url): return hashlib.md5(url.encode()).hexdigest()  # etag cache key`.
`python/tests/test_auth.py` (truth: SHA-1 in test context): `import hashlib; def test_legacy(): assert hashlib.sha1(b"x").hexdigest()`.
`java/PaymentCrypto.java` (truth: Cipher AES/CBC/PKCS5Padding, KeyPairGenerator RSA 2048, Signature SHA256withECDSA, MessageDigest MD5, DESede):
```java
import javax.crypto.Cipher; import java.security.*;
public class PaymentCrypto {
  Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
  KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); { kpg.initialize(2048); }
  Signature s = Signature.getInstance("SHA256withECDSA");
  MessageDigest md = MessageDigest.getInstance("MD5");
  Cipher legacy = Cipher.getInstance("DESede/CBC/PKCS5Padding");
}
```
`go/main.go` (truth: rsa.GenerateKey 4096, ecdsa P256, sha256, aes.NewCipher, x/crypto ssh): imports `crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/sha256`, `crypto/aes`, `crypto/cipher`, `crypto/rand`; `rsa.GenerateKey(rand.Reader, 4096)`, `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`, `sha256.Sum256(b)`, `aes.NewCipher(key)`, `cipher.NewGCM(block)`.
`js/server.js` (truth: createHash md5, createCipheriv aes-256-gcm, generateKeyPairSync rsa 2048, node-forge): `const crypto=require('crypto'); crypto.createHash('md5'); crypto.createCipheriv('aes-256-gcm', key, iv); crypto.generateKeyPairSync('rsa',{modulusLength:2048}); const forge=require('node-forge'); forge.pki.rsa.generateKeyPair(1024);`
`c/legacy.c` (truth: OpenSSL RSA_generate_key_ex, AES_set_encrypt_key, MD5_Init, EVP_sha1): includes `<openssl/rsa.h>`, `<openssl/aes.h>`, `<openssl/md5.h>`; calls `RSA_generate_key_ex(rsa, 2048, e, NULL)`, `AES_set_encrypt_key(k, 128, &aes)`, `MD5_Init(&ctx)`, `EVP_sha1()`.
`nginx/nginx.conf` (truth: TLSv1.2 TLSv1.3, ssl_ciphers string, ssl_ecdh_curve prime256v1): `ssl_protocols TLSv1.2 TLSv1.3; ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305; ssl_ecdh_curve prime256v1; ssl_certificate /etc/ssl/certs/pay.crt;`
`openssl.cnf`: `[system_default_sect] MinProtocol = TLSv1.2 CipherString = DEFAULT@SECLEVEL=2`.

- [ ] **Step 2: Write `source_patterns.yaml`** (schema: `languages: {python: {extensions: [.py], calls: [{callee: "rsa.generate_private_key", algorithm: RSA, primitive: pke, function: keygen, key_size_kw: key_size, key_size_pos: 1}, {callee: "ec.generate_private_key", algorithm: ECDSA, curve_arg: 0}, {callee: "hashlib.md5", algorithm: MD5, primitive: hash}, {callee: "hashlib.sha1", algorithm: SHA-1}, {callee: "hashlib.sha256", algorithm: SHA-256}, {callee: "hashes.MD5", ...}, {callee: "hashes.SHA256"}, {callee: "AESGCM", algorithm: AES, mode: GCM, key_size_kw: bit_length}, {callee: "algorithms.AES", algorithm: AES}, {callee: "algorithms.TripleDES", algorithm: 3DES}, {callee: "modes.ECB", mode: ECB}, {callee: "modes.CBC", mode: CBC}, {callee: "padding.OAEP", algorithm: RSA, padding: OAEP, function: encrypt}, {callee: "ec.ECDSA", algorithm: ECDSA, function: sign}, {callee: "x25519.X25519PrivateKey.generate", algorithm: X25519}, {callee: "ed25519.Ed25519PrivateKey.generate", algorithm: Ed25519}, {callee: "Crypto.Cipher.AES.new"/"AES.new", algorithm: AES}, {callee: "RSA.generate", algorithm: RSA, key_size_pos: 0}], imports: [{module: "cryptography", library: pyca-cryptography}, {module: "Crypto", library: pycryptodome}, {module: "hashlib", library: stdlib}]}, java: {extensions [.java], string_calls: [{callee: "Cipher.getInstance", parse: "transformation"}, {callee: "KeyPairGenerator.getInstance", parse: "algorithm", function: keygen}, {callee: "Signature.getInstance", parse: "signature"}, {callee: "MessageDigest.getInstance", parse: "algorithm", primitive: hash}, {callee: "KeyGenerator.getInstance", parse: "algorithm"}, {callee: "Mac.getInstance"}, {callee: "KeyAgreement.getInstance"}, {callee: "SSLContext.getInstance", parse: "protocol"}], calls: [{callee: "initialize", key_size_pos: 0, attach_to_previous: KeyPairGenerator}]}, go: {calls: [{callee: "rsa.GenerateKey", algorithm: RSA, key_size_pos: 1}, {callee: "ecdsa.GenerateKey", algorithm: ECDSA, curve_arg: 0}, {callee: "elliptic.P256", curve: P-256}, {callee: "sha256.Sum256"/"sha256.New", algorithm: SHA-256}, {callee: "sha1.New", algorithm: SHA-1}, {callee: "md5.New"/"md5.Sum", algorithm: MD5}, {callee: "aes.NewCipher", algorithm: AES}, {callee: "cipher.NewGCM", mode: GCM}, {callee: "des.NewTripleDESCipher", algorithm: 3DES}, {callee: "rc4.NewCipher", algorithm: RC4}, {callee: "ed25519.GenerateKey", algorithm: Ed25519}, {callee: "ecdh.X25519", algorithm: X25519}, {callee: "mlkem.GenerateKey768", algorithm: ML-KEM-768}], imports: [{module: "crypto/rsa"...}]}, javascript: {calls: [{callee: "crypto.createHash", string_arg: 0}, {callee: "crypto.createCipheriv", string_arg: 0}, {callee: "crypto.createDecipheriv", string_arg: 0}, {callee: "crypto.generateKeyPairSync", string_arg: 0, key_size_kw: modulusLength}, {callee: "crypto.createHmac", algorithm: HMAC}, {callee: "forge.pki.rsa.generateKeyPair", algorithm: RSA, key_size_pos: 0}, {callee: "CryptoJS.MD5", algorithm: MD5}, {callee: "CryptoJS.AES.encrypt", algorithm: AES}]}, c: {calls: [{callee: "RSA_generate_key_ex", algorithm: RSA, key_size_pos: 1}, {callee: "RSA_generate_key", key_size_pos: 0}, {callee: "AES_set_encrypt_key", algorithm: AES, key_size_pos: 1}, {callee: "MD5_Init"/"MD5"/"EVP_md5", algorithm: MD5}, {callee: "EVP_sha1"/"SHA1_Init", algorithm: SHA-1}, {callee: "EVP_sha256", algorithm: SHA-256}, {callee: "EVP_aes_256_gcm", algorithm: AES-256, mode: GCM}, {callee: "EVP_aes_128_cbc", algorithm: AES-128, mode: CBC}, {callee: "EC_KEY_new_by_curve_name", algorithm: ECDSA}, {callee: "DES_set_key", algorithm: DES}, {callee: "EVP_PKEY_CTX_new_id"...}], includes: [{header: "openssl/", library: openssl}]}, config: {files: ["nginx.conf", "*.conf", "openssl.cnf", "sshd_config", "*.properties", "*.yaml", "*.yml", "*.toml", "*.env", "*.ini"], directives: [{key: "ssl_protocols", protocol: TLS, parse: versions}, {key: "ssl_ciphers", protocol: TLS, parse: cipher_string}, {key: "ssl_ecdh_curve", parse: curves}, {key: "MinProtocol"}, {key: "CipherString"}, {key: "Ciphers", protocol: SSH}, {key: "KexAlgorithms", protocol: SSH}, {key: "SSLProtocol", protocol: TLS}, {key: "SSLCipherSuite"}]}}`).

- [ ] **Step 3: Write failing tests**

```python
# tests/test_source.py
from pathlib import Path
from ecdat.collectors.base import Target
from ecdat.collectors.source import SourceCollector
from ecdat.knowledge import KnowledgeBase
ZOO = Path(__file__).parent/"fixtures"/"zoo"/"src"
kb = KnowledgeBase()
def _names(findings): return {(f.name, f.props.get("key_size")) for f in findings}
def test_python_finds_rsa_ecdsa_aes_sha256():
    fs = SourceCollector().collect(Target(kind="dir", path=str(ZOO/"python"), name="py", zone="internal"), kb)
    names = _names(fs)
    assert ("RSA", 2048) in names and ("ECDSA", None) in names and ("AES-256", 256) in names and ("SHA-256", None) in names
def test_python_context_flags():
    fs = SourceCollector().collect(Target("dir", str(ZOO/"python"), "py", "internal"), kb)
    md5 = [f for f in fs if f.name == "MD5"][0]; assert md5.context["is_test"] is False
    sha1 = [f for f in fs if f.name == "SHA-1"][0]; assert sha1.context["is_test"] is True
def test_java_transformation_parsing():
    fs = SourceCollector().collect(Target("dir", str(ZOO/"java"), "java", "internal"), kb)
    aes = [f for f in fs if f.name == "AES"][0]; assert aes.props["mode"] == "CBC" and aes.props["padding"] == "PKCS5Padding"
    assert ("RSA", 2048) in _names(fs) and ("3DES", None) in _names(fs) and ("MD5", None) in _names(fs)
def test_go_js_c():
    assert ("RSA", 4096) in _names(SourceCollector().collect(Target("dir", str(ZOO/"go"), "go", "internal"), kb))
    js = _names(SourceCollector().collect(Target("dir", str(ZOO/"js"), "js", "external"), kb))
    assert ("MD5", None) in js and ("AES-256", 256) in js and ("RSA", 2048) in js and ("RSA", 1024) in js
    c = _names(SourceCollector().collect(Target("dir", str(ZOO/"c"), "c", "internal"), kb))
    assert ("RSA", 2048) in c and ("AES-128", 128) in c and ("MD5", None) in c
def test_nginx_protocol_finding():
    fs = SourceCollector().collect(Target("dir", str(ZOO/"nginx"), "nginx", "external"), kb)
    tls = [f for f in fs if f.asset_type == "protocol"][0]
    assert "TLSv1.2" in tls.props["versions"] and any("ECDHE-RSA-AES256-GCM-SHA384" in s for s in tls.props["cipher_suites"])
```

- [ ] **Step 4: Implement `source.py`**: for each file by extension → language; parse with tree-sitter (`tree_sitter_python.language()` etc.); walk nodes; for `call` / `call_expression` / `method_invocation` nodes get callee text (dotted), args list; match pattern by callee suffix (`endswith`), extract key size from kwarg or positional int literal, string literal arg for Java transformation (`"AES/CBC/PKCS5Padding"` → algorithm AES, mode CBC, padding PKCS5Padding; `"SHA256withECDSA"` → ECDSA + hash SHA-256; `"DESede/..."` → 3DES), JS string arg (`'aes-256-gcm'` → AES-256 GCM, `'md5'` → MD5, `'rsa'` + modulusLength). Import findings → `related-crypto-material`? No: emit `RawFinding(asset_type='algorithm', name=lib)`… simpler: emit a finding with `props={'library': name}` and `asset_type='library'` handled by dependency merge (we treat libraries as Components with `provides` edges). Comments: tree-sitter `comment` nodes → regex scan for algorithm names → `in_comment=True, confidence=low`. Regex fallback for unknown extensions (.rb, .php, .rs, .kt, .cs, .swift): scan algorithm alias words with word boundaries, confidence low. Config files: line parser for directives. Context: `is_test` if any path part in {test, tests, spec, __tests__, testdata} or filename starts with `test_`/ends with `_test`/`.test.`/`.spec.`; `is_vendored` if path part in {vendor, node_modules, third_party, external}.

- [ ] **Step 5: Run tests** → PASS. Commit "feat: source collector".

---

### Task 3: OpenGrep engine + context classification

**Files:** Create `ecdat/collectors/opengrep.py`, `ecdat/enrich/context.py`; Test `tests/test_opengrep.py`, `tests/test_context.py`.

**Interfaces:**
- `OpenGrepCollector().available() -> bool`; `.collect(target, kb)` runs `opengrep scan --config tools/semgrep-crypto-rules --json --quiet <path>`, maps each result to `RawFinding(collector="opengrep", name=<canonical via rule-id keywords md5|sha1|rsa|des|rc4|blowfish|ecb|aes...>, confidence="medium", props={"rule": check_id, "message":...})`.
- `context.classify(asset_or_finding) -> dict(usage: 'security'|'non-security'|'unknown', is_test, is_vendored, in_comment, reason)`: non-security if hash primitive and line/identifier context matches `(cache|etag|checksum|uuid|fingerprint|dedup|filename|bucket|shard|hash_key)` and not `(password|passwd|token|secret|sign|auth|hmac|session)`.

- [ ] Tests: `test_opengrep_finds_rsa1024_and_md5()` (skip if `not available()`), runs on `tests/fixtures/zoo/src/python` and asserts a finding with name MD5 exists; `test_context_non_security_md5()` uses line `hashlib.md5(url.encode()).hexdigest()  # etag cache key` → usage non-security; `test_context_security_md5()` line `hashlib.md5(password.encode())` → security.
- [ ] Implement; run; commit "feat: opengrep engine and context classification".

---

### Task 4: Dependency collector

**Files:** `ecdat/collectors/dependency.py`, `ecdat/knowledge/library_signatures.yaml`, fixtures `zoo/src/python/requirements.txt` (cryptography==42.0.5, pycryptodome==3.20.0, pyjwt==2.8.0, requests), `zoo/src/js/package.json` (node-forge, jsonwebtoken, crypto-js, bcrypt), `zoo/src/go/go.mod` (go 1.22; golang.org/x/crypto), `zoo/src/java/pom.xml` (org.bouncycastle:bcprov-jdk18on:1.78), test `tests/test_dependency.py`.

**Interfaces:** `DependencyCollector().collect(target, kb)` → `RawFinding(asset_type="library", name=<package>, props={"ecosystem": "pypi"|"npm"|"go"|"maven", "version": v, "provides": [canonical algos], "runtime": {"go": "1.22"} when go.mod})`. `library_signatures.yaml`: `pypi: {cryptography: {provides: [RSA, ECDSA, ECDH, X25519, Ed25519, AES-128, AES-256, ChaCha20, SHA-256, SHA-1, MD5, 3DES, HMAC, PBKDF2], pqc_native: false}, pycryptodome: {...}, pyjwt: {provides: [HMAC, RSA, ECDSA]}, kyber-py: {provides: [ML-KEM-768], pqc_native: true}, dilithium-py: {...}}, npm: {node-forge: {provides: [RSA, AES-128, AES-256, MD5, SHA-1, SHA-256, 3DES, RC4]}, jsonwebtoken: [...], crypto-js: [...], bcrypt: [bcrypt]}, go: {golang.org/x/crypto: [ChaCha20, Ed25519, X25519, bcrypt, scrypt, Argon2, SSH]}, maven: {org.bouncycastle:bcprov-jdk18on: {provides: [RSA, ECDSA, AES-256, ML-KEM-768, ML-DSA-65, ...], pqc_native_from: "1.79"}}`. Runtime PQC table: `runtimes: {go: {pqc_native_from: "1.24"}, java: {pqc_native_from: "24"}, openssl: {pqc_native_from: "3.5"}, python: {pqc_native: false}}`. Syft optional: if `tools.find("syft")`, run `syft dir:<path> -o cyclonedx-json` and add packages not seen by manifests (confidence medium).

- [ ] Tests: requirements/pom/package.json/go.mod each yield expected library findings; `go.mod` yields `props.runtime == {"go":"1.22"}`; provides list for `cryptography` contains RSA. Implement; run; commit.

---

### Task 5: Certificate & key collector

**Files:** `ecdat/collectors/certificate.py`, `scripts/build_zoo.py` (part 1: certs + keystore), tests `tests/test_certificate.py`.

**Build zoo artefacts (script, uses openssl + keytool on PATH):** `zoo/certs/rsa2048_sha256.crt` (+key), `ecdsa_p256.crt`, `rsa1024_sha1_expired.crt` (`-days -1` not allowed → generate with `-days 1` and `openssl x509 -set_startdate`? Simpler: generate with `-days 365` then also generate `rsa4096.crt`; expiry checked via notValidAfter < now only for a hand-crafted cert using cryptography lib in the script with `not_valid_after = 2020-01-01`), `bundle.pem` (chain), `pay.p12` (PKCS#12 with password "zoo"), `keystore.jks` (keytool `-genkeypair -keyalg RSA -keysize 2048 -storepass zoopass -alias pay`), `truth.yaml`.

**Interfaces:** `CertificateCollector().collect(target, kb)` → for each cert: `RawFinding(asset_type="certificate", name=<subject CN>, props={subject, issuer, serial, not_before, not_after, signature_algorithm (canonical + oid), public_key_algorithm (canonical), key_size, curve, sha256_fingerprint, format:"X.509", extension:".crt", is_ca, san, self_signed, expired})` plus one `algorithm` finding for the public key algorithm and one for the signature hash; for private keys: `related-crypto-material` with `{type:"private-key", algorithm, size, format}`. PKCS#12 via `cryptography.hazmat.primitives.serialization.pkcs12.load_key_and_certificates` with passwords from `target.props.get("passwords", ["", "changeit", "password", "zoo"])`; JKS via `jks.KeyStore.load(path, pw)` trying the same list; on failure emit a `related-crypto-material` finding `{type:"keystore", locked:true}` with confidence low. If theia is available, also run `cbomkit-theia dir <path>` and merge its `components` (assetType related-crypto-material for secrets) as `collector="theia"`.

- [ ] Tests: build zoo certs in a fixture (`scripts.build_zoo.build_certs(tmp_path)`), then assert RSA-2048 cert has `public_key_algorithm == "RSA"`, `key_size == 2048`, `signature_algorithm == "RSA"` with hash SHA-256; expired cert has `expired True`; ECDSA cert has `curve == "secp256r1"`; JKS yields an RSA-2048 private key finding; PKCS#12 yields cert + key. Implement; run; commit.

---

### Task 6: Binary collector

**Files:** `ecdat/collectors/binary.py`, `scripts/build_zoo.py` (part 2: compile `zoo/bin/zoobin` from `zoo/src/go/main.go` with `go build`; also a tiny C program? Go only), tests `tests/test_binary.py`.

**Interfaces:** `BinaryCollector().collect(target, kb)`: for each file where `base.is_binary(path)` (ELF/PE/Mach-O magic or .so/.dll/.exe/.bin/.a/.jar/.class/.wasm): (1) YARA scan with `tools/findcrypt3.rules` → rule names like `AES_TE0`, `SHA256_Constants`, `RSA_public_key`… mapped to canonical algorithms via a table in `binary.py` (`{"AES": "AES", "SHA256": "SHA-256", "SHA1": "SHA-1", "MD5": "MD5", "DES": "DES", "RC4": "RC4", "Blowfish": "Blowfish", "SHA512": "SHA-512", "RIPEMD": "RIPEMD-160", "CRC32": None}`); (2) `lief.parse` → imported/exported symbol names matched against `{RSA_, EVP_, AES_, SHA256_, MD5_, EC_KEY, mbedtls_, CryptEncrypt, BCrypt}`; (3) version strings: regex `OpenSSL \d+\.\d+\.\d+`, `mbed TLS \d`, `LibreSSL`, `wolfSSL`, `BoringSSL` over printable strings → `library` finding with version; (4) Go binaries: `strings` for `crypto/rsa`, `crypto/ecdsa`, `crypto/aes`, `crypto/sha256`, `crypto/tls`, `crypto/mlkem` package paths → algorithm findings (Go embeds import paths). Confidence: yara constants medium, symbols medium, strings low. `props={"method": "yara"|"symbol"|"string", "rule": ...}`, `context={"best_effort": True}`. JAR files: unzip, scan class names for `javax/crypto`, `java/security`, `org/bouncycastle`.

- [ ] Tests: build zoobin (skip if `go` absent) and assert findings include SHA-256 and AES with `method in {yara,string}`; a PE test on `tools/opengrep.exe`? (large; skip) — instead write a synthetic binary file containing the AES S-box bytes and SHA-256 K constants and assert YARA finds `AES` and `SHA-256`. Implement; run; commit.

---

### Task 7: Container collector

**Files:** `ecdat/collectors/container.py`, `scripts/build_zoo.py` (part 3: `zoo/images/zoo-oci.tar` built in pure Python: OCI layout with `oci-layout`, `index.json`, blobs: config + one tar.gz layer containing `/etc/ssl/certs/pay.crt` (rsa2048 cert), `/etc/nginx/nginx.conf`, `/etc/ssl/openssl.cnf`, `/usr/lib/libcrypto.so.1.1` (synthetic bytes with "OpenSSL 1.1.1w" string + AES S-box), `/app/requirements.txt`), tests `tests/test_container.py`.

**Interfaces:** `ContainerCollector().collect(target, kb)`: detect docker-save tar (`manifest.json`) vs OCI tar (`index.json`) vs plain OCI dir; extract layers in order to a temp rootfs (handle whiteouts `.wh.`), then run `SourceCollector`, `DependencyCollector`, `CertificateCollector`, `BinaryCollector` over the rootfs with `component = target.name` and `location` prefixed `image://<name>/<path>`; also image config → `props.image = {os, architecture, created, layers: n}`. If `crane` is available and target.path is not a file, `crane pull <ref> <tmp>.tar` first. If theia is available, run `cbomkit-theia image <tar>` (or `dir` on rootfs) and merge components as `collector="theia"`.

- [ ] Tests: build `zoo-oci.tar` via script into tmp; collect; assert a certificate finding with `location.startswith("image://")`, a protocol finding from nginx.conf, a library finding `OpenSSL 1.1.1w`. Implement; run; commit.

---

### Task 8: Protocol collector (live TLS + SSH)

**Files:** `ecdat/collectors/protocol.py`, tests `tests/test_protocol.py` (starts a local TLS server thread with a zoo cert on an ephemeral port).

**Interfaces:** `ProtocolCollector().collect(target, kb)` where `target.kind == "endpoints"` and `target.path` is a file with lines `host:port[ tls|ssh|smtp-starttls]` or `target.props["endpoints"]` list. TLS: try cryptolyzer (`from cryptolyzer.tls.versions import AnalyzerVersions; from cryptolyzer.tls.ciphers import AnalyzerCipherSuites; from cryptolyzer.tls.curves import AnalyzerCurves; from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys; from cryptolyzer.tls.client import L7ClientTlsBase`) with a 10 s timeout; fallback `ssl.create_default_context()` handshake (CERT_NONE, `check_hostname=False`) reporting `version()`, `cipher()`, `getpeercert(binary_form=True)`; additionally a raw ClientHello via scapy advertising `supported_groups` including `x25519_mlkem768 (0x11EC)` to detect PQ KEX support (parse ServerHello key_share group). Emit `protocol` finding `{type:"tls", versions:[...], cipher_suites:[...], kex_groups:[...], pq_kex: bool, negotiated: {...}}` plus certificate findings (reuse `certificate.parse_x509(der)`), plus algorithm findings for KEX (ECDH/X25519/RSA-KEX) and signature. SSH: connect, read banner, send our KEXINIT and parse server KEXINIT name-lists (`kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_client_to_server`) → protocol finding `{type:"ssh", kex:[...], hostkey:[...], ciphers:[...], pq_kex: "sntrup761x25519-sha512" or "mlkem768x25519-sha256" in kex}`.

- [ ] Tests: local `ssl.SSLContext(PROTOCOL_TLS_SERVER)` server with rsa2048 cert; collect against `127.0.0.1:port tls`; assert protocol finding has `"TLSv1.3"` in versions (or negotiated) and a certificate finding with CN `zoo.local`; SSH test uses a fake server thread that sends banner `SSH-2.0-zoo` and a KEXINIT packet with `curve25519-sha256,ecdh-sha2-nistp256` → assert `kex` parsed. Implement; run; commit.

---

### Task 9: Pcap collector

**Files:** `ecdat/collectors/pcap.py`, `scripts/build_zoo.py` (part 4: `zoo/pcaps/tls_handshake.pcap` built with scapy TLS layers: ClientHello (TLS 1.2, suites incl. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, groups x25519/secp256r1) + ServerHello (selects that suite) + Certificate (rsa2048 cert DER); plus `smtp_starttls.pcap`: TCP 25 with `220 ...`, `EHLO`, `STARTTLS`, `220 Ready`, then ClientHello TLS 1.0 with `TLS_RSA_WITH_3DES_EDE_CBC_SHA` selected), tests `tests/test_pcap.py`.

**Interfaces:** `PcapCollector().collect(target, kb)` (`kind == "pcap"`): `scapy.load_layer("tls")`, `rdpcap`, group by 4-tuple, walk `TLSClientHello`/`TLSServerHello`/`TLSCertificate`; emit per session a `protocol` finding `{type:"tls", version, cipher_suite (negotiated), offered_suites, kex_group, sni, starttls: bool, app_protocol: "smtp"|"imap"|"pop3"|"https"|"unknown"}`; certificate findings from `TLSCertificate` DER blobs; algorithm findings from suite parts (ECDHE → ECDH, RSA kex → RSA, AES-256-GCM → AES-256, 3DES → 3DES, SHA → SHA-1 MAC). If tshark available, cross-check with `tshark -r <pcap> -Y tls.handshake -T fields -e tls.handshake.ciphersuite -e tls.handshake.version` and mark `corroborated=True`.

- [ ] Tests: build pcaps; assert the https session negotiates `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` and a cert CN `zoo.local` is extracted; the SMTP pcap yields `starttls True`, `app_protocol smtp`, and a `3DES` algorithm finding. Implement; run; commit.

---

### Task 10: Merge, CycloneDX 1.7 emission, signing, CERT-In completeness

**Files:** `ecdat/normalize/merge.py`, `ecdat/normalize/cyclonedx.py`, `ecdat/normalize/signing.py`, `ecdat/normalize/certin.py`, `ecdat/collectors/__init__.py`, tests `tests/test_merge.py`, `tests/test_cyclonedx.py`, `tests/test_signing.py`, `tests/test_certin.py`.

**Interfaces:**
- `merge.merge(findings: list[RawFinding], components: list[Component], kb) -> list[CryptoAsset]`: key = `(component, asset_type, canonical name, key_size, mode)` for algorithms; `(component, "certificate", sha256_fingerprint)` for certs; `(component, "protocol", type, location)` for protocols; `(component, "library", name, version)` for libraries → Components of type `library` with `provides` edges (library assets get `provided_by`). Evidence appended; confidence = max; if ≥2 distinct collectors → `context["corroborated"]=True` and confidence bumped one level (max high). Library-provided algorithms are NOT emitted as usage assets unless a source/binary finding exists; they are emitted as assets with `context["from_library_only"]=True` and confidence low (inventory completeness) — flag in reports.
- `cyclonedx.to_bom(result: ScanResult) -> dict` (specVersion "1.7", `metadata.tools.components` = ecdat + engine versions, `components`: applications/containers/libraries + `cryptographic-asset` components with `cryptoProperties` per type, `evidence.occurrences` with location/line, `properties` for ecdat fields (`ecdat:confidence`, `ecdat:tier`, `ecdat:agility`, `ecdat:lifetime_years`, `ecdat:usage`, `ecdat:hndl_applicable`), `dependencies` with `dependsOn` and `provides`), `cyclonedx.validate(bom: dict) -> list[str]` using `jsonschema.Draft7Validator` with a `referencing` registry mapping `spdx.schema.json` and `jsf-0.82.schema.json` to vendored files, `cyclonedx.write(bom, path)`.
- `signing.keygen() -> (pk_bytes, sk_bytes)`, `signing.sign(bom_bytes, sk) -> sig`, `signing.verify(bom_bytes, sig, pk) -> bool` with ML-DSA-65; `signing.sign_file(bom_path, key_dir)` writes `<bom>.mldsa65.sig` and `ecdat-mldsa65.pub`.
- `certin.completeness(asset) -> (present: list[str], missing: list[str], pct: float)` per Table 9 by asset type; `certin.summary(assets) -> {by_type: {...}, overall_pct}`.

- [ ] Tests: merge two RSA-2048 findings from source+opengrep into one asset with 2 evidence and `corroborated`; BOM validates (`validate(bom) == []`) for a small result; every asset has `cryptoProperties.assetType`; sign/verify roundtrip true and tamper → false; completeness for a full cert = 100%, for an algorithm missing OID < 100%. Implement; run; commit.

---

### Task 11: Enrichment (exposure, lifetime, criticality, agility)

**Files:** `ecdat/enrich/exposure.py`, `ecdat/enrich/lifetime.py`, `ecdat/enrich/agility.py`, `ecdat/knowledge/data_classes.yaml`, tests `tests/test_enrich.py`.

**Interfaces:**
- `exposure.assign(asset, component) -> dict(zone, transit: bool, at_rest: bool, signing_only: bool, reason)`: zone from component/target; `transit` if protocol/live/pcap evidence or KEX primitive; `signing_only` if primitive == signature or cert used only for signing; `at_rest` for block/stream ciphers in source.
- `lifetime.infer(component, asset, kb) -> (years: float, data_class: str, reason)`: explicit override → else path/identifier hints from `data_classes.yaml` (`health: {years: 25, hints: [patient, ehr, medical, diagnosis, hipaa]}, financial: {years: 10, hints: [payment, card, pan, ledger, bank, kyc, upi]}, identity: {years: 20, hints: [aadhaar, passport, identity, kyc, biometric]}, defence: {years: 30, hints: [classified, defence, defense, mil, strategic]}, pii: {years: 7, hints: [user, customer, email, phone, address, profile]}, session: {years: 0.1, hints: [session, token, jwt, cookie, cache]}, logs: {years: 1, hints: [log, audit, metric]}, generic: {years: 5}`); `lifetime.criticality_multiplier(level) -> float` with `{low: 0.8, medium: 1.0, high: 1.25, critical: 1.5}` (QRAMM profile range).
- `agility.score(asset, all_assets) -> AgilityScore(dimensions: dict[str, float 0..1], total: int 0..100, y_years: float, reasons: list[str])` with dimensions: `algorithm_coupling` (1.0 if algorithm name is a string literal/API constant at call site, 0.3 if from variable/config), `provider_coupling` (1.0 direct low-level API like `hazmat`/`javax.crypto`/`crypto/rsa`/OpenSSL C; 0.5 via framework wrapper like `pyjwt`/`spring-security`; 0.2 via TLS termination config), `parameter_coupling` (1.0 key size literal, 0.4 default, 0.2 config), `decoupling` (0.0 if a config/env reference for the algorithm exists in the same file else 1.0), `spread` (min(1, call_sites/10) blended with files/5), `ownership` (0.2 first-party source, 0.6 vendored/dependency, 1.0 opaque binary/container-only), `runtime_pqc` (0.0 if runtime has native PQC — Go>=1.24, Java>=24, OpenSSL>=3.5, BC>=1.79 detected in dependency findings; 0.6 if a PQC library is installable; 1.0 for C/embedded without). `total = round(100 * (1 - weighted_mean))` with weights `{algorithm_coupling: .15, provider_coupling: .15, parameter_coupling: .10, decoupling: .15, spread: .15, ownership: .15, runtime_pqc: .15}`; `y_years` by asset type & total: certificate → 0.5; protocol config → 0.5; algorithm: `1.0 + 4.0 * (1 - total/100)` (so 1 y when fully agile, 5 y when rigid), ×2 for binary-only evidence (cap 10).

- [ ] Tests: RSA hardcoded across many files scores lower than a single config-driven use; certificate y=0.5; `lifetime.infer` for `payments/auth.py` → financial 10 y; multiplier map. Implement; run; commit.

---

### Task 12: Risk engine

**Files:** `ecdat/risk/quantum.py`, `ecdat/risk/mosca.py`, `ecdat/risk/frameworks.py`, `ecdat/knowledge/frameworks.yaml`, tests `tests/test_risk.py`.

**Interfaces:**
- `quantum.classify(asset, kb) -> dict(quantum_class, reason, hndl_applicable: bool, confidentiality: bool)`; `hndl_applicable = quantum_class in {broken, weakened} and primitive in CONFIDENTIALITY and exposure.transit or exposure.at_rest`.
- `mosca.assess(asset, params) -> RiskAssessment(x, y, z, mosca_gap: float = x + y - z_years_from_now, tier: 'EXPOSED'|'ACT_NOW'|'MONITOR'|'SAFE', priority: float, deadline_year: int|None, reasons)` where `z_years = params.z_year - params.now_year`; rules: SAFE if quantum_class == safe or usage == non-security; EXPOSED if hndl_applicable and x + y > z_years; ACT_NOW if (quantum_class in {broken, legacy-broken}) and (x + y > z_years - 2 or earliest framework deadline − now ≤ y + 1); MONITOR otherwise for weakened/broken; `priority = criticality_mult * (3 if EXPOSED else 2 if ACT_NOW else 1 if MONITOR else 0) * (1.5 if exposure.zone == "external" else 1.0) * (1 + min(x, 30)/30)`.
- `frameworks.overlays(asset, params) -> list[dict(framework, rule, status: 'violation'|'warning'|'ok', deadline_year, text)]` from `frameworks.yaml`: `dst_india: {profile_cii: {M1: 2027 inventory, M2: 2028 no_new_classical, M3: 2029 quantum_safe_only}, profile_enterprise: {2028, 2030, 2033}}`, `nist_ir_8547: {deprecate: 2030 (RSA/ECC/DH 112-bit), disallow: 2035}`, `cnsa_2_0: {web_browsers_servers_cloud: {prefer: 2025, exclusive: 2033}, networking_equipment: {support: 2026, exclusive: 2030}, aes_min: 256, sha_min: 384, sig: ML-DSA-87, kem: ML-KEM-1024}`, `cert_in_v2: {formats: [CycloneDX, SPDX], vex_required: true, review_months: 3}`, `eu_pqc: {high_risk: 2030, all: 2035}`, `uk_ncsc: {discovery: 2028, priority: 2031, complete: 2035}`.
- `mosca.recompute(result: ScanResult, params: ScanParams) -> ScanResult` re-runs assess for all assets (used by the Z slider).

- [ ] Tests: RSA key-exchange asset, x=10, y=3, z_year 2035 (9 y) → EXPOSED; same with z 2041 (15 y) → ACT_NOW or MONITOR per rule; ECDSA signature never EXPOSED (hndl false) but ACT_NOW under DST CII (M2 2028); MD5 non-security → SAFE; AES-256 → SAFE; CNSA overlay flags AES-128 as violation. Implement; run; commit.

---

### Task 13: Planner (PQC mapping, optimiser, VEX, patches)

**Files:** `ecdat/plan/pqc.py`, `ecdat/plan/optimizer.py`, `ecdat/plan/vex.py`, `ecdat/plan/patches.py`, `ecdat/knowledge/pqc_mappings.yaml`, tests `tests/test_plan.py`.

**Interfaces:**
- `pqc_mappings.yaml`: `targets: {X25519MLKEM768: {fips: [FIPS 203], type: hybrid-kem, pubkey_bytes: 1216, ciphertext_bytes: 1120, vs: {X25519: {pubkey_bytes: 32}}, latency_note: "+~0.2 ms handshake, +1.1 KB per key share", supported_by: [openssl>=3.5, go>=1.24, java>=24, chrome, firefox, cloudflare]}, ML-KEM-768: {pubkey 1184, ct 1088, nist_level 3}, ML-KEM-1024: {1568, 1568, level 5, cnsa: true}, ML-DSA-65: {fips: [FIPS 204], pubkey 1952, sig 3309, vs ECDSA-P256 sig 64, RSA-2048 sig 256, level 3}, ML-DSA-87: {2592, 4627, level 5, cnsa}, SLH-DSA-SHA2-128s: {fips 205, sig 7856, stateless hash-based}, FN-DSA-512: {fips 206 draft, sig 666}, AES-256: {...}, SHA-384: {...}}`, `rules: [{from_primitive: key-agree|kem|pke, from_class: broken, to: X25519MLKEM768, alt: ML-KEM-768, cnsa: ML-KEM-1024}, {from_primitive: signature, from_class: broken, to: ML-DSA-65, alt: SLH-DSA-SHA2-128s, cnsa: ML-DSA-87}, {from: AES-128, to: AES-256}, {from: MD5|SHA-1, to: SHA-256, note: classical hygiene not PQC}, {from: 3DES|DES|RC4|Blowfish, to: AES-256-GCM}, {from: SHA-256 hash in signatures under CNSA, to: SHA-384}]`, `runtime_support: {python: {kem: kyber-py|liboqs-python, sig: dilithium-py|liboqs-python, native: false}, go: {native_from: "1.24", packages: [crypto/mlkem], sig_native_from: "1.27"}, java: {native_from: "24", jeps: [496, 497]}, openssl: {native_from: "3.5"}, node: {native: false, packages: [@noble/post-quantum, liboqs-node]}, c: {liboqs, oqs-provider}}`.
- `pqc.recommend(asset, kb, params) -> Recommendation(target, alternative, cnsa_target, fips, deltas: dict, runtime_note, effort_weeks: float, hybrid: bool, rationale)`; `effort_weeks = base_by_type (cert 1, config 1, algorithm 2) * (1 + (100 - agility.total)/25) * spread_factor`.
- `optimizer.plan(assets, engineers, months) -> Plan(items: [(asset, risk_reduction, effort_weeks, cumulative_weeks, cumulative_risk_pct)], capacity_weeks, covered_pct, uncovered: [...])`: risk value = `priority`; greedy by `priority/effort_weeks` until capacity `engineers * months * 4.33`; certificates and configs first when tie.
- `vex.build(result) -> dict` CycloneDX `vulnerabilities` array: one entry per non-SAFE asset with `id: "ECDAT-QV-<n>"`, `source: {name: "ECDAT quantum risk"}`, `ratings: [{method: "other", severity: critical|high|medium|low, justification}]`, `analysis: {state: "affected"|"not_affected"|"resolved"|"in_triage", justification: "code_not_reachable" for test-only, "protected_by_mitigating_control" for hybrid}`, `affects: [{ref: bom_ref}]`; merged into the BOM by `cyclonedx.to_bom` when present.
- `patches.suggest(asset) -> list[Patch(title, file, unified_diff, note)]` for: python pyca `rsa.generate_private_key` (→ `from kyber_py.ml_kem import ML_KEM_768; ek, dk = ML_KEM_768.keygen()` with note "hybrid: keep X25519 alongside"), Java `KeyPairGenerator.getInstance("RSA")` (→ `"ML-KEM"` with `NamedParameterSpec.ML_KEM_768`, JDK 24+), Go `rsa.GenerateKey` (→ `mlkem.GenerateKey768()`), nginx `ssl_ecdh_curve` (→ `X25519MLKEM768:X25519:prime256v1`, OpenSSL 3.5+), Java `Signature.getInstance("SHA256withECDSA")` (→ `"ML-DSA-65"`), `hashlib.md5` in security use (→ `hashlib.sha256`).

- [ ] Tests: RSA kex → X25519MLKEM768 with deltas present; ECDSA → ML-DSA-65; plan with 4 engineers × 6 months covers highest priority first and `cumulative_weeks ≤ capacity`; VEX has one entry per non-safe asset and validates inside the BOM; patch for pyca RSA contains `ML_KEM_768`. Implement; run; commit.

---

### Task 14: Exports (SARIF, CSV, HTML, PDF)

**Files:** `ecdat/export/sarif.py`, `ecdat/export/csv_export.py`, `ecdat/export/html_report.py`, `ecdat/export/pdf_report.py`, tests `tests/test_export.py`.

**Interfaces:** `sarif.to_sarif(result) -> dict` (2.1.0, one rule per canonical algorithm, results with `physicalLocation`), `csv_export.write(result, path)` (RFC 4180, formula-injection hardened: prefix `=+-@` with `'`), `html_report.render(result) -> str` (self-contained, inline CSS, sections: executive summary with tier counts and DST milestones, 2x2 SVG scatter, asset table, plan, CERT-In completeness, methodology + honesty notes incl. binary best-effort and Z assumption), `pdf_report.write(result, path)` via reportlab (executive 2 pages + technical appendix table).

- [ ] Tests: SARIF has `runs[0].results` length == asset count with location; CSV first cell hardened; HTML contains "ALREADY EXPOSED" section and Z value; PDF file > 10 KB. Implement; run; commit.

---

### Task 15: Pipeline, config, CLI, end-to-end on the zoo

**Files:** `ecdat/config.py`, `ecdat/pipeline.py`, `ecdat/cli.py`, `tests/fixtures/zoo/ecdat.yaml`, tests `tests/test_pipeline.py`, `tests/test_cli.py`.

**Interfaces:**
- `ecdat.yaml` schema:
```yaml
name: zoo-scan
params: {z_year: 2041, engineers: 4, months: 6, profile: cii, now_year: 2026}
targets:
  - {kind: dir, path: tests/fixtures/zoo/src/python, name: payments-api, zone: external, data_class: financial, criticality: high}
  - {kind: dir, path: tests/fixtures/zoo/src/java, name: core-banking, zone: internal, data_class: financial, criticality: critical}
  - {kind: dir, path: tests/fixtures/zoo/src/go, name: gateway, zone: external}
  - {kind: dir, path: tests/fixtures/zoo/src/js, name: web-portal, zone: external, data_class: pii}
  - {kind: dir, path: tests/fixtures/zoo/src/c, name: legacy-hsm-agent, zone: internal, data_class: defence, criticality: critical}
  - {kind: dir, path: tests/fixtures/zoo/src/nginx, name: edge-lb, zone: external}
  - {kind: certs, path: tests/fixtures/zoo/certs, name: pki, zone: external}
  - {kind: dir, path: tests/fixtures/zoo/bin, name: zoobin, zone: internal}
  - {kind: image, path: tests/fixtures/zoo/images/zoo-oci.tar, name: pay-image, zone: external}
  - {kind: pcap, path: tests/fixtures/zoo/pcaps/smtp_starttls.pcap, name: mail-capture, zone: external}
```
- `pipeline.run(config: ScanConfig, progress=None) -> ScanResult` executes: collectors → merge → context → exposure → lifetime → agility → quantum → mosca → frameworks → pqc → vex → plan; `pipeline.write_outputs(result, out_dir)` writes `cbom.json` (+ `.mldsa65.sig`, `ecdat-mldsa65.pub`), `vex.json`, `result.json` (full analysis incl. plan), `findings.sarif`, `assets.csv`, `report.html`, `report.pdf`, `summary.md`.
- CLI (`typer`): `ecdat scan -c ecdat.yaml -o out/ [--z-year 2035] [--engineers 4 --months 6] [--no-external-tools]`, `ecdat report out/result.json --format html|pdf|md`, `ecdat recompute out/result.json --z-year 2032 --engineers 2 --months 3`, `ecdat zoo build`, `ecdat eval out/result.json --truth tests/fixtures/zoo/truth.yaml`, `ecdat gate ...` (Task 17), `ecdat serve out/` (Task 18), `ecdat tools` (prints engine availability + versions).

- [ ] Tests: `pipeline.run` on the zoo config produces ≥ 25 assets, a valid CBOM, at least one EXPOSED asset (the C legacy agent: defence 30 y + RSA), at least one SAFE asset, a plan whose first item has the highest priority/effort ratio; CLI `scan` via `typer.testing.CliRunner` writes all output files. Implement; run; commit.

---

### Task 16: Zoo truth + evaluation

**Files:** `tests/fixtures/zoo/truth.yaml`, `ecdat/eval.py`, tests `tests/test_eval.py`.

**Interfaces:** `truth.yaml` lists expected `(component, name, key_size?, asset_type)` tuples per collector plus `negatives` (things that must NOT appear, e.g. `("payments-api","MD5",usage:"security")`); `eval.evaluate(result, truth) -> dict(per_collector: {tp, fp, fn, precision, recall, f1}, overall, missed: [...], extra: [...])`; CLI prints a table and writes `eval.json`. Target on zoo: precision ≥ 0.85, recall ≥ 0.95 (test asserts these).

- [ ] Implement; run; commit "feat: evaluation harness".

---

### Task 17: CI gate + GitHub Action

**Files:** `ecdat/gate.py`, `.github/workflows/ecdat-gate.yml`, `action/` (Dockerfile-less composite action running `pip install . && ecdat gate`), tests `tests/test_gate.py`.

**Interfaces:** `gate.compare(baseline_bom: dict, current_bom: dict, policy: 'no-new-vulnerable'|'no-vulnerable'|'dst-m2') -> GateResult(passed: bool, new_vulnerable: [...], removed: [...], summary_md)`; identity of an asset for diff = `(component, name, key_size, mode, location-file)`; `dst-m2` policy fails on any new asset with quantum_class broken in an external zone. CLI `ecdat gate --baseline out/cbom.json --config ecdat.yaml --policy no-new-vulnerable` exits 1 on failure and prints markdown (also writes `gate.md` for PR comments).

- [ ] Tests: baseline without RSA vs current with new RSA → fail; same BOM → pass; removal → pass with note. Implement; run; commit.

---

### Task 18: API server

**Files:** `ecdat/api/server.py`, tests `tests/test_api.py` (httpx AsyncClient / TestClient).

**Interfaces:** FastAPI app `create_app(results_dir: Path)`; routes: `GET /api/health`, `GET /api/tools`, `GET /api/results` (list scans), `GET /api/results/{id}` (full result.json), `POST /api/results/{id}/recompute {z_year, engineers, months, profile}` → recomputed result (in memory, not persisted), `GET /api/results/{id}/cbom`, `/vex`, `/sarif`, `/csv`, `/report.html`, `/report.pdf`, `POST /api/scan {config_yaml}` → runs pipeline in a background thread, returns `{id}`; `GET /api/scan/{id}/status` streams progress; static mount of `web/dist` at `/`. CORS enabled for dev.

- [ ] Tests: health 200; results list contains the zoo scan; recompute with z_year 2032 increases EXPOSED count vs 2041; cbom endpoint returns specVersion 1.7. Implement; run; commit.

---

### Task 19: Web dashboard

**Files:** `web/package.json`, `web/vite.config.ts`, `web/index.html`, `web/src/main.tsx`, `web/src/App.tsx`, `web/src/api.ts`, `web/src/types.ts`, `web/src/views/Overview.tsx` (tier buckets, DST M1/M2/M3 panel, CERT-In completeness gauge, collector coverage), `web/src/views/Matrix.tsx` (SVG 2x2 scatter: x = agility 0..100 reversed as "harder →", y = priority, colour by tier, click → drawer), `web/src/views/Assets.tsx` (table with filters, drill-down drawer showing evidence file:line/snippet, cryptoProperties, overlays, recommendation with deltas, patch diff), `web/src/views/Plan.tsx` (engineers/months inputs, ordered list, cumulative risk curve SVG), `web/src/components/ZSlider.tsx` (presets 2032/2035/2041 + range; calls recompute and re-renders everything), `web/src/components/Export.tsx`, `web/src/styles.css` (dark, one accent, IBM Plex fonts via @fontsource like FreightMind), tests: `web/src/__tests__/tier.test.ts` (vitest for a pure helper) and a Playwright smoke script `scripts/ui_smoke.py` that starts the API, opens the dashboard, screenshots `docs/screenshots/*.png`.

- [ ] Steps: `npm create vite@latest` (react-ts) → install → implement views → `npm run build` → `ecdat serve out/` → Playwright screenshot of Overview, Matrix, Plan; assert page contains "ALREADY EXPOSED" and the Z slider changes the count. Commit.

---

### Task 20: Docs, demo script, real-repo run

**Files:** `README.md`, `docs/DEMO_SCRIPT.md`, `docs/AIRGAP_INSTALL.md`, `docs/screenshots/`, `out/real-*/` (git-ignored) results of scanning a real OSS repo cloned into `$CLAUDE_JOB_DIR/tmp` (e.g. `https://github.com/jpadilla/pyjwt` and `https://github.com/python-jose/python-jose`, both in the 2026 auditor paper's corpus) plus the live endpoint `cloudflare.com:443` (expect `pq_kex True`) and `example.com:443`.

- [ ] Steps: write README (install online / air-gapped wheelhouse via `pip download -d wheels` and `pip install --no-index --find-links wheels`), tools table with versions, CLI reference, config reference, honesty notes; run the real scans and paste summary tables into `docs/REAL_RUNS.md`; final full `pytest`; commit "docs: readme, demo script, real runs".

---

## Self-review

- Spec coverage: L1 (Task 15 config), L2 six collectors (Tasks 2–9), L3 (Task 10), L4 (Task 3 + 11), L5 (Task 12), L6 (Task 13), L7 (Tasks 14, 17, 18, 19), YAML knowledge (Tasks 1, 2, 4, 11, 12, 13), honesty rules (confidence in Task 1 model; best-effort in Task 6; Z slider Tasks 12/18/19; HNDL scope Task 12; patches as suggestions Task 13; precision published Task 16), evaluation (Task 16), demo (Task 20), CERT-In Table 9 (Task 10), DST overlays (Task 12), CI gate = M2 (Task 17), air-gapped (Task 20 docs; no network in tests), signed CBOM (Task 10).
- Placeholder scan: none of the banned phrases; every task has concrete test assertions and named implementations.
- Type consistency: `RawFinding`/`CryptoAsset`/`Target`/`ScanParams`/`ScanResult` names are used identically across tasks; `agility.total`, `risk.tier`, `recommendation.effort_weeks`, `exposure.zone` referenced consistently.
