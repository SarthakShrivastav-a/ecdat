# ECDAT scan: OpenVPN__easy-rsa

- id: `eddfd9c0dbcc`  time: 2026-09-18T08:35:09.032094+00:00  duration: 35.03 s
- targets: 1  components: 1  libraries: 2  assets: 25
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 11
- MONITOR: 6
- SAFE: 8

## CERT-In Table 9 completeness: 80.0%

- algorithm: 81.5%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 79.2% of risk with 102.5 eng-weeks; 3 items left over

1. Blowfish [OpenVPN/easy-rsa] tier=ACT_NOW -> AES-256-GCM  9.5 wk
2. RC4 [OpenVPN/easy-rsa] tier=ACT_NOW -> AES-256-GCM  10.0 wk
3. Ed25519 [OpenVPN/easy-rsa] tier=ACT_NOW -> ML-DSA-65  8.5 wk
4. key:generic-api-key [OpenVPN/easy-rsa] tier=MONITOR -> None  4.4 wk
5. DH [OpenVPN/easy-rsa] tier=ACT_NOW -> X25519MLKEM768  9.5 wk
6. DSA [OpenVPN/easy-rsa] tier=ACT_NOW -> ML-DSA-65  9.6 wk
7. DES [OpenVPN/easy-rsa] tier=ACT_NOW -> AES-256-GCM  12.1 wk
8. ECDH [OpenVPN/easy-rsa] tier=ACT_NOW -> X25519MLKEM768  11.0 wk
9. MD5 [OpenVPN/easy-rsa] tier=ACT_NOW -> SHA-256  15.2 wk
10. ECDSA [OpenVPN/easy-rsa] tier=ACT_NOW -> ML-DSA-65  12.7 wk

## Collectors

- source: 39
- opengrep: 0
- dependency: 0
- certificate: 1
- binary: 109

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
