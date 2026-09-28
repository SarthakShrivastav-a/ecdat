# ECDAT scan: inji__inji-wallet

- id: `1bd9e654655c`  time: 2026-09-18T09:06:05.171084+00:00  duration: 27.02 s
- targets: 1  components: 1  libraries: 10  assets: 37
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 1
- MONITOR: 19
- SAFE: 16

## CERT-In Table 9 completeness: 63.7%

- algorithm: 66.9%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 38.8 eng-weeks; 0 items left over

1. RSA [inji/inji-wallet] tier=EXPOSED -> ML-KEM-768  8.9 wk
2. AES [inji/inji-wallet] tier=ACT_NOW -> AES-256  7.7 wk
3. key:generic-api-key [inji/inji-wallet] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [inji/inji-wallet] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [inji/inji-wallet] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [inji/inji-wallet] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [inji/inji-wallet] tier=MONITOR -> None  4.6 wk

## Collectors

- source: 15
- opengrep: 0
- dependency: 9
- certificate: 8
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
