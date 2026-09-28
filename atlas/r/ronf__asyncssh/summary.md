# ECDAT scan: ronf__asyncssh

- id: `2ca1dd20b2ac`  time: 2026-09-18T08:10:53.938974+00:00  duration: 32.52 s
- targets: 1  components: 1  libraries: 6  assets: 28
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 5
- MONITOR: 8
- SAFE: 15

## CERT-In Table 9 completeness: 69.9%

- algorithm: 74.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 56.1 eng-weeks; 0 items left over

1. DSA [ronf/asyncssh] tier=ACT_NOW -> ML-DSA-65  7.9 wk
2. X25519 [ronf/asyncssh] tier=ACT_NOW -> X25519MLKEM768  7.9 wk
3. ECDH [ronf/asyncssh] tier=ACT_NOW -> X25519MLKEM768  8.8 wk
4. key:generic-api-key [ronf/asyncssh] tier=MONITOR -> None  4.4 wk
5. ECDSA [ronf/asyncssh] tier=ACT_NOW -> ML-DSA-65  9.0 wk
6. RSA [ronf/asyncssh] tier=ACT_NOW -> ML-KEM-768  10.6 wk
7. AES [ronf/asyncssh] tier=MONITOR -> AES-256  7.5 wk

## Collectors

- source: 67
- opengrep: 0
- dependency: 5
- certificate: 45
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
