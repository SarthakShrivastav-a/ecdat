# ECDAT scan: Bahmni__openmrs-module-bahmniapps

- id: `dc0ac0dd405e`  time: 2026-09-18T08:24:18.929190+00:00  duration: 87.02 s
- targets: 1  components: 1  libraries: 0  assets: 3
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 2
- SAFE: 1

## CERT-In Table 9 completeness: 42.9%

- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 8.8 eng-weeks; 0 items left over

1. key:generic-api-key [Bahmni/openmrs-module-bahmniapps] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [Bahmni/openmrs-module-bahmniapps] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 0
- opengrep: 0
- dependency: 0
- certificate: 4
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
