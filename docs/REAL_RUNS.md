# Real-world runs (2026-09-05)

Three public open-source repositories (downloaded as zip archives with `scripts/fetch_real.py`) plus four live public
endpoints, scanned with `ecdat scan -c out/real-src/ecdat.yaml -o out/real-world` on this Windows laptop. All engines
were available (OpenGrep, Syft, cbomkit-theia, tshark, CryptoLyzer). Z = 2041, profile = enterprise, budget 4 engineers x 6 months.

## Summary

| | value |
|---|---|
| assets | 159 (pyjwt 43, node-jsonwebtoken 33, paramiko 60, public endpoints 23) |
| tiers | EXPOSED 0 · ACT_NOW 21 · MONITOR 16 · SAFE 122 |
| CBOM | CycloneDX 1.7, schema-valid, ML-DSA-65 signed |
| CERT-In Table 9 completeness | 71.6% |
| raw findings per collector | source 277, certificate 179, protocol 61, dependency 8, opengrep 0, binary 0 |

No asset lands in EXPOSED because the configured data classes are short-lived (session tokens, PII 7 y) and none of the repos
hold long-lived secrets in code; change `data_class` to `health` or `defence` and the same RSA usage becomes EXPOSED.

## Live endpoints (the "we ask the server" slide)

| endpoint | negotiated | key exchange | post-quantum | certificate | tier |
|---|---|---|---|---|---|
| cloudflare.com:443 | TLS 1.3, TLS_AES_256_GCM_SHA384 | **X25519MLKEM768** | yes | ECDSA P-256, SHA-256, Google Trust Services | SAFE |
| example.com:443 | TLS 1.3, TLS_AES_256_GCM_SHA384 | **X25519MLKEM768** | yes | ECDSA P-256, SHA-256, Cloudflare/SSL Corp | SAFE |
| github.com:22 | SSH-2.0 | offers **sntrup761x25519-sha512** first, then curve25519 / nistp256-521 / DH group-exchange | yes | Ed25519 host keys | SAFE |
| www.nic.in:443 | TLS 1.3 (1.2 also enabled), TLS_AES_256_GCM_SHA384 | x25519 only | **no** | RSA-2048, SHA-256, Let's Encrypt | MONITOR |

The probe offers X25519MLKEM768 and SecP256r1MLKEM768 in a raw ClientHello and reads the group in the server's key_share.
Cloudflare-fronted hosts pick the hybrid; the Indian government host does not. That single row is the M2 conversation
("no new classical-only deployments by 2028") made concrete.

## Repositories

- **pyjwt** (Python): RSA / ECDSA / Ed25519 / HMAC signing paths via pyca cryptography; 8 ACT_NOW (RSA and ECDSA JWS signing,
  deadline-driven under NIST 2030 / DST 2030), 7 MONITOR, 28 SAFE (HMAC, SHA-2, test-only and comment mentions).
- **node-jsonwebtoken** (JavaScript): only `crypto.createSign` / `createVerify` wrappers, HMAC and hashes -> 33 SAFE
  (algorithm names arrive as variables, so the source collector records them at medium confidence with `literal: false`).
- **paramiko** (Python, SSH library): 60 assets. 3DES and DES-based legacy ciphers, DH groups, RSA/DSA/ECDSA host keys ->
  7 ACT_NOW (3DES first in the plan: classically broken today), 1 MONITOR, 52 SAFE (AES-GCM/CTR, ChaCha20, Ed25519 helpers, tests).

## Top of the migration plan (4 engineers x 6 months)

1. cloudflare.com / example.com / www.nic.in certificates -> plan re-issuance with ML-DSA-65 when the CA supports FIPS 204 (2.2 wk each)
2. public-endpoints TLS -> enable X25519MLKEM768 on the terminator (2.4 wk)
3. paramiko 3DES -> AES-256-GCM (8.0 wk, legacy-broken)
4. public-endpoints DH / ECDH -> X25519MLKEM768 (7.5 wk each)
5. public-endpoints Ed25519 host keys -> ML-DSA-65 (7.5 wk)

## Caveats
- Repositories are libraries, not deployed systems: exposure and data lifetime are configuration assumptions here.
- OpenGrep produced no findings on these repos with the crypto rule set (the code uses wrappers the rules do not target);
  the tree-sitter engine carried detection. This is visible in the per-collector table, not hidden.
- Endpoint results are a snapshot; re-run before quoting them.
