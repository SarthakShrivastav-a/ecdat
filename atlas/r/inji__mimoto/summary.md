# ECDAT scan: inji__mimoto

- id: `181ab68966bb`  time: 2026-09-18T08:15:05.870319+00:00  duration: 43.9 s
- targets: 1  components: 1  libraries: 8  assets: 69
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 4
- MONITOR: 42
- SAFE: 20

## CERT-In Table 9 completeness: 68.4%

- algorithm: 72.8%
- certificate: 100.0%
- key: 46.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 67.7% of risk with 103.2 eng-weeks; 13 items left over

1. RootCA [inji/mimoto] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [inji/mimoto] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [inji/mimoto] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [inji/mimoto] tier=EXPOSED -> None  4.4 wk
5. SHA-1 [inji/mimoto] tier=ACT_NOW -> SHA-256  8.0 wk
6. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
7. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
8. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
9. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
10. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
11. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
12. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
13. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
14. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk
15. pkcs12-keystore [inji/mimoto] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 199
- opengrep: 0
- dependency: 4
- certificate: 56
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
