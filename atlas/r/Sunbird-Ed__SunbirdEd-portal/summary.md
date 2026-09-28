# ECDAT scan: Sunbird-Ed__SunbirdEd-portal

- id: `692664ac1951`  time: 2026-09-18T09:07:36.902066+00:00  duration: 85.08 s
- targets: 1  components: 1  libraries: 6  assets: 38
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 13
- SAFE: 24

## CERT-In Table 9 completeness: 57.2%

- algorithm: 72.3%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 30.1 eng-weeks; 0 items left over

1. key:generic-api-key [Sunbird-Ed/SunbirdEd-portal] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [Sunbird-Ed/SunbirdEd-portal] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [Sunbird-Ed/SunbirdEd-portal] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [Sunbird-Ed/SunbirdEd-portal] tier=MONITOR -> None  4.5 wk
5. MD5 [Sunbird-Ed/SunbirdEd-portal] tier=ACT_NOW -> SHA-256  12.4 wk

## Collectors

- source: 22
- opengrep: 0
- dependency: 6
- certificate: 60
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
