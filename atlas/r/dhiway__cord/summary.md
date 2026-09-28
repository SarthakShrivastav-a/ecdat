# ECDAT scan: dhiway__cord

- id: `282ce4344285`  time: 2026-09-18T08:21:22.106111+00:00  duration: 75.68 s
- targets: 1  components: 1  libraries: 9  assets: 27
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 2
- ACT_NOW: 2
- MONITOR: 13
- SAFE: 10

## CERT-In Table 9 completeness: 63.5%

- algorithm: 73.8%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 95.8 eng-weeks; 0 items left over

1. ECDH [dhiway/cord] tier=EXPOSED -> X25519MLKEM768  8.0 wk
2. X25519 [dhiway/cord] tier=EXPOSED -> X25519MLKEM768  12.5 wk
3. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.5 wk
8. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.6 wk
9. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.6 wk
10. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.8 wk
11. key:generic-api-key [dhiway/cord] tier=MONITOR -> None  4.8 wk
12. Ed25519 [dhiway/cord] tier=ACT_NOW -> ML-DSA-65  17.1 wk
13. ECDSA [dhiway/cord] tier=ACT_NOW -> ML-DSA-65  17.3 wk

## Collectors

- source: 1311
- opengrep: 0
- dependency: 9
- certificate: 35
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
