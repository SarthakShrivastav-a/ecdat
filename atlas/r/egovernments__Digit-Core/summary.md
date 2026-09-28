# ECDAT scan: egovernments__Digit-Core

- id: `3387763d88d9`  time: 2026-09-18T09:20:52.713757+00:00  duration: 58.3 s
- targets: 1  components: 1  libraries: 9  assets: 120
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 91
- SAFE: 28

## CERT-In Table 9 completeness: 47.5%

- algorithm: 71.4%
- protocol: 60.0%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 28.9% of risk with 102.0 eng-weeks; 58 items left over

1. TLS [egovernments/Digit-Core] tier=MONITOR -> X25519MLKEM768  2.6 wk
2. TLS [egovernments/Digit-Core] tier=MONITOR -> X25519MLKEM768  2.6 wk
3. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
8. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [egovernments/Digit-Core] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 125
- opengrep: 0
- dependency: 6
- certificate: 116
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
