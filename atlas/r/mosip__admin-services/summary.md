# ECDAT scan: mosip__admin-services

- id: `d5399c60b6ef`  time: 2026-09-18T08:43:02.664388+00:00  duration: 52.37 s
- targets: 1  components: 1  libraries: 3  assets: 8
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 2
- SAFE: 5

## CERT-In Table 9 completeness: 69.1%

- algorithm: 95.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 16.5 eng-weeks; 0 items left over

1. RSA [mosip/admin-services] tier=EXPOSED -> ML-KEM-768  7.7 wk
2. key:generic-api-key [mosip/admin-services] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [mosip/admin-services] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 50
- opengrep: 0
- dependency: 1
- certificate: 6
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
