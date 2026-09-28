# ECDAT scan: paulmillr__noble-curves

- id: `42ec85332322`  time: 2026-09-18T08:17:21.851899+00:00  duration: 38.24 s
- targets: 1  components: 1  libraries: 5  assets: 14
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 2
- SAFE: 12

## CERT-In Table 9 completeness: 71.4%

- algorithm: 79.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 0.0 eng-weeks; 0 items left over


## Collectors

- source: 103
- opengrep: 0
- dependency: 5
- certificate: 65
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
