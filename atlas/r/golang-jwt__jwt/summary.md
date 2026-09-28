# ECDAT scan: golang-jwt__jwt

- id: `35b708fed4fa`  time: 2026-09-18T09:43:30.014296+00:00  duration: 17.24 s
- targets: 1  components: 1  libraries: 2  assets: 22
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 0
- SAFE: 21

## CERT-In Table 9 completeness: 71.4%

- algorithm: 100.0%
- key: 57.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 12.7 eng-weeks; 0 items left over

1. RSA [golang-jwt/jwt] tier=ACT_NOW -> ML-KEM-768  12.7 wk

## Collectors

- source: 35
- opengrep: 0
- dependency: 1
- certificate: 39
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
