# ECDAT scan: mosip__registration

- id: `c17905918ff0`  time: 2026-09-18T09:15:51.251299+00:00  duration: 57.59 s
- targets: 1  components: 1  libraries: 8  assets: 20
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 10
- SAFE: 9

## CERT-In Table 9 completeness: 61.9%

- algorithm: 67.3%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 12.7 eng-weeks; 0 items left over

1. RSA [mosip/registration] tier=EXPOSED -> ML-KEM-768  8.3 wk
2. key:generic-api-key [mosip/registration] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 39
- opengrep: 0
- dependency: 4
- certificate: 8
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
