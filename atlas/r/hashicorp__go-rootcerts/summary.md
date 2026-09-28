# ECDAT scan: hashicorp__go-rootcerts

- id: `2139b5a75443`  time: 2026-09-18T09:39:40.033211+00:00  duration: 14.23 s
- targets: 1  components: 1  libraries: 1  assets: 10
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 1
- SAFE: 9

## CERT-In Table 9 completeness: 81.1%

- algorithm: 100.0%
- protocol: 40.0%
- certificate: 100.0%
- key: 57.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 1.9 eng-weeks; 0 items left over

1. TLS [hashicorp/go-rootcerts] tier=MONITOR -> X25519MLKEM768  1.9 wk

## Collectors

- source: 3
- opengrep: 0
- dependency: 1
- certificate: 27
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
