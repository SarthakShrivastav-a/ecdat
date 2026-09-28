# ECDAT scan: mattermost__mattermost-plugin-starter-template

- id: `36742326584a`  time: 2026-09-18T08:54:33.703758+00:00  duration: 13.3 s
- targets: 1  components: 1  libraries: 2  assets: 12
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 5
- SAFE: 7

## CERT-In Table 9 completeness: 58.3%

- key: 42.9%
- algorithm: 59.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 4.5 eng-weeks; 0 items left over

1. key:generic-api-key [mattermost/mattermost-plugin-starter-template] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 0
- opengrep: 0
- dependency: 2
- certificate: 2
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
