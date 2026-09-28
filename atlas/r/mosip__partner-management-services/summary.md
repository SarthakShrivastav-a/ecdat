# ECDAT scan: mosip__partner-management-services

- id: `99ebb1eee884`  time: 2026-09-18T08:35:24.242415+00:00  duration: 36.2 s
- targets: 1  components: 1  libraries: 4  assets: 4
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 3
- SAFE: 0

## CERT-In Table 9 completeness: 61.9%

- algorithm: 100.0%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 22.5 eng-weeks; 0 items left over

1. RSA [mosip/partner-management-services] tier=EXPOSED -> ML-KEM-768  9.3 wk
2. key:generic-api-key [mosip/partner-management-services] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [mosip/partner-management-services] tier=MONITOR -> None  4.4 wk
4. token:jwt [mosip/partner-management-services] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 45
- opengrep: 0
- dependency: 2
- certificate: 3
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
