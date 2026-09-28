# ECDAT scan: hyperledger__fabric-sdk-node

- id: `7e489531c72f`  time: 2026-09-18T08:26:43.210634+00:00  duration: 133.22 s
- targets: 1  components: 1  libraries: 2  assets: 20
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 0
- SAFE: 20

## CERT-In Table 9 completeness: 69.7%

- algorithm: 95.2%
- protocol: 60.0%
- certificate: 100.0%
- key: 48.6%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 0.0 eng-weeks; 0 items left over


## Collectors

- source: 272
- opengrep: 0
- dependency: 2
- certificate: 15
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
