# ECDAT scan: auth0__java-jwt

- id: `6da856a4fc09`  time: 2026-09-18T09:43:52.039345+00:00  duration: 19.77 s
- targets: 1  components: 1  libraries: 4  assets: 63
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 14
- SAFE: 49

## CERT-In Table 9 completeness: 62.5%

- algorithm: 70.5%
- key: 50.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 8.8 eng-weeks; 0 items left over

1. token:jwt [auth0/java-jwt] tier=MONITOR -> None  4.4 wk
2. token:jwt [auth0/java-jwt] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 78
- opengrep: 0
- dependency: 1
- certificate: 268
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
