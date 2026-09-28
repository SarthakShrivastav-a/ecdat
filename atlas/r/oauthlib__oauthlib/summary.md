# ECDAT scan: oauthlib__oauthlib

- id: `ce2718e9e674`  time: 2026-09-18T08:55:18.782681+00:00  duration: 17.34 s
- targets: 1  components: 1  libraries: 2  assets: 40
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 11
- SAFE: 28

## CERT-In Table 9 completeness: 60.7%

- algorithm: 72.8%
- key: 47.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 20.7 eng-weeks; 0 items left over

1. key:generic-api-key [oauthlib/oauthlib] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [oauthlib/oauthlib] tier=MONITOR -> None  4.5 wk
3. SHA-1 [oauthlib/oauthlib] tier=ACT_NOW -> SHA-256  11.8 wk

## Collectors

- source: 44
- opengrep: 0
- dependency: 2
- certificate: 58
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
