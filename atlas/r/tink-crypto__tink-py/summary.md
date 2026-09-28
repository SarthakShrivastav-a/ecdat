# ECDAT scan: tink-crypto__tink-py

- id: `cb3041c95c0e`  time: 2026-09-18T08:54:57.806174+00:00  duration: 20.78 s
- targets: 1  components: 1  libraries: 7  assets: 47
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 19
- SAFE: 28

## CERT-In Table 9 completeness: 60.4%

- algorithm: 74.7%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 49.9 eng-weeks; 0 items left over

1. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.4 wk
2. token:aws-access-token [tink-crypto/tink-py] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.5 wk
4. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.5 wk
5. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.5 wk
6. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.5 wk
7. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.5 wk
8. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.6 wk
9. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.6 wk
10. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.6 wk
11. key:generic-api-key [tink-crypto/tink-py] tier=MONITOR -> None  4.8 wk

## Collectors

- source: 92
- opengrep: 0
- dependency: 7
- certificate: 50
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
