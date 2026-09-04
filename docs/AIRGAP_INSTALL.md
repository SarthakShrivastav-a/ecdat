# Air-gapped installation

NTRO / NCIIPC networks have no internet. ECDAT needs none at scan time: the knowledge base, schemas, YARA rules and
OpenGrep rules ship inside the package; no vulnerability database is downloaded; signing keys are generated locally.

## 1. Build a wheelhouse on a connected machine (same OS + Python minor version)

```powershell
python -m pip download -d wheelhouse cryptography cyclonedx-python-lib lief scapy "tree-sitter>=0.25" tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-go tree-sitter-c yara-python fastapi "uvicorn[standard]" pyyaml typer rich jsonschema reportlab dilithium-py kyber-py httpx python-multipart cryptolyzer pycryptodomex pyasn1 pyasn1-modules javaobj-py3 pyjks
python -m pip wheel . -w wheelhouse --no-deps
```

Copy to the target: `wheelhouse/`, `tools/` (opengrep.exe, syft.exe, findcrypt3.rules, semgrep-crypto-rules/), and the Go
binaries `cbomkit-theia.exe` and `crane.exe` if you want container/registry support. The dashboard is pre-built in `web/dist/`.

## 2. Install offline

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --no-index --find-links wheelhouse ecdat
.\.venv\Scripts\python -m pip install --no-index --find-links wheelhouse --no-deps pyjks
set ECDAT_TOOLS_DIR=C:\ecdat\tools
.\.venv\Scripts\ecdat tools
```

## 3. Verify with the built-in corpus

```powershell
ecdat zoo build          # needs openssl + keytool on PATH for the keystore artefacts; skips them otherwise
ecdat scan -c tests/fixtures/zoo/ecdat.yaml -o out/zoo
ecdat evaluate out/zoo/result.json --strict
```

## What still needs a network (and is optional)
- live endpoint probing (`kind: endpoints`) obviously talks to the hosts you list, nothing else
- `crane pull` for registry references; use image tars instead (`docker save` / `skopeo copy`)
- Syft has no network dependency for directory scans

## Signing
`ecdat scan` creates `keys/ecdat-mldsa65.key` next to the output directory on first use. Protect it like any signing key;
copy `ecdat-mldsa65.pub` to whoever verifies the CBOM: `python -c "from ecdat.normalize import signing; print(signing.verify_file(Path('out/zoo/cbom.json')))"`.
