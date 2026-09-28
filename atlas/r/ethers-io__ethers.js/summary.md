# ECDAT scan: ethers-io__ethers.js

- id: `67492500d313`  time: 2026-09-18T09:02:02.306017+00:00  duration: 47.75 s
- targets: 1  components: 1  libraries: 3  assets: 28
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 21
- SAFE: 7

## CERT-In Table 9 completeness: 56.7%

- algorithm: 81.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 80.5 eng-weeks; 0 items left over

1. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
8. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [ethers-io/ethers.js] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 46
- opengrep: 0
- dependency: 3
- certificate: 402
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
