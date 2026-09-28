# ECDAT scan: indutny__elliptic

- id: `c01431ddffef`  time: 2026-09-18T08:54:18.616012+00:00  duration: 17.23 s
- targets: 1  components: 1  libraries: 1  assets: 8
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 3
- SAFE: 5

## CERT-In Table 9 completeness: 71.4%

- algorithm: 80.9%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 4.4 eng-weeks; 0 items left over

1. private-key:private-key [indutny/elliptic] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 5
- opengrep: 0
- dependency: 1
- certificate: 6
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
