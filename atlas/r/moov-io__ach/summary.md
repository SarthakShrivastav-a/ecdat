# ECDAT scan: moov-io__ach

- id: `9e19880e38c9`  time: 2026-09-18T08:33:27.287804+00:00  duration: 35.09 s
- targets: 1  components: 1  libraries: 1  assets: 5
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 1
- SAFE: 3

## CERT-In Table 9 completeness: 80.6%

- algorithm: 85.7%
- protocol: 60.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 10.7 eng-weeks; 0 items left over

1. TLS [moov-io/ach] tier=MONITOR -> X25519MLKEM768  2.2 wk
2. AES [moov-io/ach] tier=ACT_NOW -> AES-256  8.5 wk

## Collectors

- source: 4
- opengrep: 0
- dependency: 1
- certificate: 0
- binary: 2

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
