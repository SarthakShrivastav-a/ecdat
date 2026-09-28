# ECDAT scan: open-quantum-safe__liboqs-python

- id: `2e011ddab532`  time: 2026-09-18T09:40:16.681422+00:00  duration: 15.79 s
- targets: 1  components: 1  libraries: 2  assets: 1
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 0
- SAFE: 1

## CERT-In Table 9 completeness: 100.0%

- algorithm: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 0.0 eng-weeks; 0 items left over


## Collectors

- source: 16
- opengrep: 0
- dependency: 1
- certificate: 0
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
