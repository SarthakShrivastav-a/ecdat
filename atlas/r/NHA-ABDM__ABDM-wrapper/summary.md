# ECDAT scan: NHA-ABDM__ABDM-wrapper

- id: `a54a37cf2841`  time: 2026-09-18T08:29:56.806346+00:00  duration: 33.13 s
- targets: 1  components: 1  libraries: 5  assets: 1
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 0
- SAFE: 0

## CERT-In Table 9 completeness: 60.0%

- protocol: 60.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 2.6 eng-weeks; 0 items left over

1. TLS [NHA-ABDM/ABDM-wrapper] tier=EXPOSED -> X25519MLKEM768  2.6 wk

## Collectors

- source: 122
- opengrep: 0
- dependency: 2
- certificate: 0
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
