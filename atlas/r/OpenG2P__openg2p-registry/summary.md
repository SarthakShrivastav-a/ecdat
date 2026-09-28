# ECDAT scan: OpenG2P__openg2p-registry

- id: `f804a189c758`  time: 2026-09-18T08:10:19.191325+00:00  duration: 39.36 s
- targets: 1  components: 1  libraries: 3  assets: 22
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 10
- SAFE: 11

## CERT-In Table 9 completeness: 72.1%

- algorithm: 73.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 13.6 eng-weeks; 0 items left over

1. SHA-1 [OpenG2P/openg2p-registry] tier=ACT_NOW -> SHA-256  9.2 wk
2. key:generic-api-key [OpenG2P/openg2p-registry] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 21
- opengrep: 0
- dependency: 2
- certificate: 1
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
