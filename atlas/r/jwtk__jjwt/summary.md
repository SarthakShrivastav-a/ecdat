# ECDAT scan: jwtk__jjwt

- id: `32e5746499c5`  time: 2026-09-18T08:09:00.514688+00:00  duration: 44.29 s
- targets: 1  components: 1  libraries: 6  assets: 94
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 9
- SAFE: 85

## CERT-In Table 9 completeness: 71.0%

- algorithm: 81.8%
- certificate: 95.0%
- key: 53.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 13.4 eng-weeks; 0 items left over

1. key:generic-api-key [jwtk/jjwt] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [jwtk/jjwt] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [jwtk/jjwt] tier=MONITOR -> None  4.6 wk

## Collectors

- source: 2165
- opengrep: 0
- dependency: 3
- certificate: 183
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
