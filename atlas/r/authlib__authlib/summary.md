# ECDAT scan: authlib__authlib

- id: `d833be74fde3`  time: 2026-09-18T08:09:00.957528+00:00  duration: 37.4 s
- targets: 1  components: 1  libraries: 5  assets: 41
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 15
- SAFE: 22

## CERT-In Table 9 completeness: 65.2%

- algorithm: 78.2%
- key: 51.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 87.9 eng-weeks; 0 items left over

1. ECDSA [authlib/authlib] tier=ACT_NOW -> ML-DSA-65  8.8 wk
2. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.5 wk
7. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.5 wk
8. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.5 wk
9. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.5 wk
10. key:generic-api-key [authlib/authlib] tier=MONITOR -> None  4.6 wk
11. SHA-1 [authlib/authlib] tier=ACT_NOW -> SHA-256  12.5 wk
12. ECDH [authlib/authlib] tier=ACT_NOW -> X25519MLKEM768  11.0 wk
13. RSA [authlib/authlib] tier=ACT_NOW -> ML-KEM-768  15.4 wk

## Collectors

- source: 126
- opengrep: 0
- dependency: 3
- certificate: 54
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
