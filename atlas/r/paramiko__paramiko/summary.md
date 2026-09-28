# ECDAT scan: paramiko__paramiko

- id: `4d7fbf454f4f`  time: 2026-09-18T08:10:52.252415+00:00  duration: 30.16 s
- targets: 1  components: 1  libraries: 5  assets: 60
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 4
- SAFE: 52

## CERT-In Table 9 completeness: 68.1%

- algorithm: 82.2%
- key: 54.8%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 55.7 eng-weeks; 0 items left over

1. ECDH [paramiko/paramiko] tier=ACT_NOW -> X25519MLKEM768  8.0 wk
2. X25519 [paramiko/paramiko] tier=ACT_NOW -> X25519MLKEM768  9.0 wk
3. ECDSA [paramiko/paramiko] tier=ACT_NOW -> ML-DSA-65  13.2 wk
4. RSA [paramiko/paramiko] tier=ACT_NOW -> ML-KEM-768  17.1 wk
5. AES [paramiko/paramiko] tier=MONITOR -> AES-256  8.4 wk

## Collectors

- source: 120
- opengrep: 0
- dependency: 4
- certificate: 76
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
