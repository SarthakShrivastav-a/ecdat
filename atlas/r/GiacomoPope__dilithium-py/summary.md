# ECDAT scan: GiacomoPope__dilithium-py

- id: `ef03d31307f8`  time: 2026-09-18T08:56:45.365940+00:00  duration: 16.88 s
- targets: 1  components: 1  libraries: 4  assets: 22
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 11
- SAFE: 11

## CERT-In Table 9 completeness: 66.6%

- algorithm: 67.8%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 7.8 eng-weeks; 0 items left over

1. AES [GiacomoPope/dilithium-py] tier=MONITOR -> AES-256  7.8 wk

## Collectors

- source: 24
- opengrep: 0
- dependency: 3
- certificate: 10
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
