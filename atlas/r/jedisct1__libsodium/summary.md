# ECDAT scan: jedisct1__libsodium

- id: `34ac7644cedd`  time: 2026-09-18T08:14:59.668824+00:00  duration: 38.51 s
- targets: 1  components: 1  libraries: 1  assets: 9
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 1
- SAFE: 6

## CERT-In Table 9 completeness: 77.8%

- algorithm: 95.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 32.1 eng-weeks; 0 items left over

1. key:generic-api-key [jedisct1/libsodium] tier=MONITOR -> None  4.5 wk
2. Ed25519 [jedisct1/libsodium] tier=ACT_NOW -> ML-DSA-65  11.1 wk
3. X25519 [jedisct1/libsodium] tier=ACT_NOW -> X25519MLKEM768  16.5 wk

## Collectors

- source: 38
- opengrep: 0
- dependency: 0
- certificate: 24
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
