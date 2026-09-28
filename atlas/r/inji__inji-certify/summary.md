# ECDAT scan: inji__inji-certify

- id: `320af1407617`  time: 2026-09-18T08:20:01.447282+00:00  duration: 46.89 s
- targets: 1  components: 1  libraries: 4  assets: 30
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 5
- MONITOR: 19
- SAFE: 3

## CERT-In Table 9 completeness: 57.2%

- algorithm: 97.1%
- certificate: 100.0%
- key: 44.2%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 76.6% of risk with 99.9 eng-weeks; 5 items left over

1. RootCA [inji/inji-certify] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [inji/inji-certify] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [inji/inji-certify] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [inji/inji-certify] tier=EXPOSED -> None  4.4 wk
5. SHA-1 [inji/inji-certify] tier=ACT_NOW -> SHA-256  9.6 wk
6. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.4 wk
8. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.4 wk
12. token:jwt [inji/inji-certify] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.5 wk
14. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.5 wk
15. key:generic-api-key [inji/inji-certify] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 132
- opengrep: 0
- dependency: 2
- certificate: 116
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
