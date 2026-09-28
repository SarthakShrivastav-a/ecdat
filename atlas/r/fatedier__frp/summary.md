# ECDAT scan: fatedier__frp

- id: `c04005efc828`  time: 2026-09-18T08:25:57.705413+00:00  duration: 31.61 s
- targets: 1  components: 1  libraries: 4  assets: 15
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 5
- SAFE: 8

## CERT-In Table 9 completeness: 66.7%

- algorithm: 68.3%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 20.7 eng-weeks; 0 items left over

1. MD5 [fatedier/frp] tier=ACT_NOW -> SHA-256  7.4 wk
2. key:generic-api-key [fatedier/frp] tier=MONITOR -> None  4.4 wk
3. RSA [fatedier/frp] tier=ACT_NOW -> ML-KEM-768  8.9 wk

## Collectors

- source: 17
- opengrep: 0
- dependency: 2
- certificate: 1
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
