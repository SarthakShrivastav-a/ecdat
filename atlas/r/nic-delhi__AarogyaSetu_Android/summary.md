# ECDAT scan: nic-delhi__AarogyaSetu_Android

- id: `48b47554393c`  time: 2026-09-18T09:41:28.016985+00:00  duration: 17.12 s
- targets: 1  components: 1  libraries: 5  assets: 1
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 0
- SAFE: 0

## CERT-In Table 9 completeness: 85.7%

- algorithm: 85.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 7.7 eng-weeks; 0 items left over

1. RSA [nic-delhi/AarogyaSetu_Android] tier=EXPOSED -> ML-KEM-768  7.7 wk

## Collectors

- source: 77
- opengrep: 0
- dependency: 2
- certificate: 0
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
