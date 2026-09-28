# ECDAT scan: bitcoin__bips

- id: `27c0d4720f18`  time: 2026-09-18T08:19:09.067024+00:00  duration: 28.81 s
- targets: 1  components: 1  libraries: 1  assets: 17
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 13
- SAFE: 4

## CERT-In Table 9 completeness: 52.1%

- algorithm: 95.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 60.1 eng-weeks; 0 items left over

1. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.5 wk
4. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.5 wk
5. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.5 wk
6. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.6 wk
7. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.6 wk
8. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.6 wk
9. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.8 wk
10. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.8 wk
11. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.8 wk
12. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.8 wk
13. key:generic-api-key [bitcoin/bips] tier=MONITOR -> None  4.8 wk

## Collectors

- source: 76
- opengrep: 0
- dependency: 1
- certificate: 408
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
