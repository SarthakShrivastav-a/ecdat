# ECDAT scan: PQClean__PQClean

- id: `3361decc3504`  time: 2026-09-18T08:56:25.257968+00:00  duration: 44.73 s
- targets: 1  components: 1  libraries: 0  assets: 4
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 0
- SAFE: 4

## CERT-In Table 9 completeness: 100.0%

- algorithm: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 0.0 eng-weeks; 0 items left over


## Collectors

- source: 320
- opengrep: 0
- dependency: 0
- certificate: 0
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
