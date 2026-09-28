# ECDAT scan: acmesh-official__acme.sh

- id: `a6c5eb245323`  time: 2026-09-18T08:12:36.009616+00:00  duration: 26.13 s
- targets: 1  components: 1  libraries: 0  assets: 14
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 5
- MONITOR: 3
- SAFE: 6

## CERT-In Table 9 completeness: 87.8%

- algorithm: 95.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 77.0 eng-weeks; 0 items left over

1. Ed25519 [acmesh-official/acme.sh] tier=ACT_NOW -> ML-DSA-65  8.4 wk
2. key:generic-api-key [acmesh-official/acme.sh] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [acmesh-official/acme.sh] tier=MONITOR -> None  4.5 wk
4. MD5 [acmesh-official/acme.sh] tier=ACT_NOW -> SHA-256  12.5 wk
5. ECDSA [acmesh-official/acme.sh] tier=ACT_NOW -> ML-DSA-65  10.2 wk
6. SHA-1 [acmesh-official/acme.sh] tier=ACT_NOW -> SHA-256  15.7 wk
7. AES-128 [acmesh-official/acme.sh] tier=MONITOR -> AES-256  6.6 wk
8. RSA [acmesh-official/acme.sh] tier=ACT_NOW -> ML-KEM-768  14.7 wk

## Collectors

- source: 349
- opengrep: 0
- dependency: 0
- certificate: 3
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
