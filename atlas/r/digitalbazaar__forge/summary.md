# ECDAT scan: digitalbazaar__forge

- id: `1452329d5d21`  time: 2026-09-18T08:09:35.780599+00:00  duration: 31.57 s
- targets: 1  components: 1  libraries: 1  assets: 31
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 3
- SAFE: 24

## CERT-In Table 9 completeness: 70.5%

- algorithm: 92.4%
- certificate: 100.0%
- key: 46.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 74.9 eng-weeks; 0 items left over

1. RSA [digitalbazaar/forge] tier=ACT_NOW -> ML-KEM-768  10.6 wk
2. key:generic-api-key [digitalbazaar/forge] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [digitalbazaar/forge] tier=MONITOR -> None  4.4 wk
4. MD5 [digitalbazaar/forge] tier=ACT_NOW -> SHA-256  15.4 wk
5. SHA-1 [digitalbazaar/forge] tier=ACT_NOW -> SHA-256  16.2 wk
6. AES [digitalbazaar/forge] tier=MONITOR -> AES-256  7.7 wk
7. RSA [digitalbazaar/forge] tier=ACT_NOW -> ML-KEM-768  16.2 wk

## Collectors

- source: 446
- opengrep: 0
- dependency: 1
- certificate: 36
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
