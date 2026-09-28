# ECDAT scan: mosip__keymanager

- id: `2a481ded606a`  time: 2026-09-18T08:10:18.619946+00:00  duration: 35.22 s
- targets: 1  components: 1  libraries: 7  assets: 33
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 10
- SAFE: 22

## CERT-In Table 9 completeness: 72.7%

- algorithm: 74.6%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 17.8 eng-weeks; 0 items left over

1. key:generic-api-key [mosip/keymanager] tier=MONITOR -> None  4.4 wk
2. SHA-1 [mosip/keymanager] tier=ACT_NOW -> SHA-256  13.4 wk

## Collectors

- source: 615
- opengrep: 0
- dependency: 4
- certificate: 3
- binary: 1

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
