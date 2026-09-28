# ECDAT scan: GiacomoPope__kyber-py

- id: `5714fae1f1e6`  time: 2026-09-18T08:57:05.306131+00:00  duration: 17.55 s
- targets: 1  components: 1  libraries: 4  assets: 21
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 11
- SAFE: 10

## CERT-In Table 9 completeness: 65.3%

- algorithm: 66.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 7.8 eng-weeks; 0 items left over

1. AES [GiacomoPope/kyber-py] tier=MONITOR -> AES-256  7.8 wk

## Collectors

- source: 24
- opengrep: 0
- dependency: 3
- certificate: 9
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
