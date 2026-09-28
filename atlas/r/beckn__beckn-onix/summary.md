# ECDAT scan: beckn__beckn-onix

- id: `63a9e34dcb91`  time: 2026-09-18T08:39:45.405041+00:00  duration: 26.96 s
- targets: 1  components: 1  libraries: 4  assets: 31
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 10
- SAFE: 19

## CERT-In Table 9 completeness: 55.3%

- algorithm: 69.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 67.9 eng-weeks; 0 items left over

1. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.5 wk
5. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.6 wk
6. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.6 wk
7. key:generic-api-key [beckn/beckn-onix] tier=MONITOR -> None  4.8 wk
8. X25519 [beckn/beckn-onix] tier=ACT_NOW -> X25519MLKEM768  12.5 wk
9. Ed25519 [beckn/beckn-onix] tier=ACT_NOW -> ML-DSA-65  15.0 wk
10. AES [beckn/beckn-onix] tier=MONITOR -> AES-256  8.7 wk

## Collectors

- source: 57
- opengrep: 0
- dependency: 2
- certificate: 50
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
