# ECDAT scan: open-quantum-safe__liboqs

- id: `9bb52c0faff6`  time: 2026-09-18T09:05:30.422902+00:00  duration: 88.8 s
- targets: 1  components: 1  libraries: 4  assets: 63
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 52
- SAFE: 10

## CERT-In Table 9 completeness: 52.1%

- protocol: 40.0%
- algorithm: 96.1%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 43.1% of risk with 100.2 eng-weeks; 31 items left over

1. TLS [open-quantum-safe/liboqs] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. SHA-1 [open-quantum-safe/liboqs] tier=ACT_NOW -> SHA-256  10.3 wk
3. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
8. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [open-quantum-safe/liboqs] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 2757
- opengrep: 0
- dependency: 2
- certificate: 53
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
