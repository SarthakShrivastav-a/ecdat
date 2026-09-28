# ECDAT scan: Samagra-Development__Doc-Generator

- id: `49fce91d7694`  time: 2026-09-18T08:55:35.815635+00:00  duration: 14.49 s
- targets: 1  components: 1  libraries: 1  assets: 1
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 1
- SAFE: 0

## CERT-In Table 9 completeness: 42.9%

- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 4.4 eng-weeks; 0 items left over

1. key:generic-api-key [Samagra-Development/Doc-Generator] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 0
- opengrep: 0
- dependency: 1
- certificate: 1
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
