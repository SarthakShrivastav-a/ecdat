# ECDAT scan: auth0__node-jsonwebtoken

- id: `c1411be1c6b0`  time: 2026-09-18T09:40:35.386697+00:00  duration: 16.91 s
- targets: 1  components: 1  libraries: 1  assets: 33
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 0
- SAFE: 33

## CERT-In Table 9 completeness: 74.9%

- algorithm: 100.0%
- key: 61.3%
- certificate: 82.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 0.0 eng-weeks; 0 items left over


## Collectors

- source: 33
- opengrep: 0
- dependency: 1
- certificate: 64
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
