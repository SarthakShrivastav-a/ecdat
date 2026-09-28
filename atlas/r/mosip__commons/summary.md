# ECDAT scan: mosip__commons

- id: `ad6ce38c1981`  time: 2026-09-18T09:03:23.046205+00:00  duration: 26.94 s
- targets: 1  components: 1  libraries: 8  assets: 34
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 16
- SAFE: 18

## CERT-In Table 9 completeness: 65.5%

- algorithm: 68.5%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 13.2 eng-weeks; 0 items left over

1. key:generic-api-key [mosip/commons] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [mosip/commons] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [mosip/commons] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 106
- opengrep: 0
- dependency: 5
- certificate: 4
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
