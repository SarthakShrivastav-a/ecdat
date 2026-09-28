# ECDAT scan: inji__inji-verify

- id: `0c9810ecfe45`  time: 2026-09-18T08:39:15.473999+00:00  duration: 30.5 s
- targets: 1  components: 1  libraries: 7  assets: 55
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 3
- MONITOR: 41
- SAFE: 8

## CERT-In Table 9 completeness: 64.8%

- algorithm: 69.6%
- certificate: 100.0%
- key: 46.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 68.7% of risk with 100.6 eng-weeks; 14 items left over

1. RootCA [inji/inji-verify] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [inji/inji-verify] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [inji/inji-verify] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [inji/inji-verify] tier=EXPOSED -> None  4.4 wk
5. RSA [inji/inji-verify] tier=EXPOSED -> ML-KEM-768  9.8 wk
6. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
7. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
8. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
9. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
10. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
11. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
12. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
13. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
14. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk
15. pkcs12-keystore [inji/inji-verify] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 69
- opengrep: 0
- dependency: 5
- certificate: 54
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
