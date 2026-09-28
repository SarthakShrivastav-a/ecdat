# ECDAT scan: mosip__resident-services

- id: `6ab6a08b802a`  time: 2026-09-18T08:43:43.117983+00:00  duration: 35.25 s
- targets: 1  components: 1  libraries: 5  assets: 39
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 2
- MONITOR: 27
- SAFE: 7

## CERT-In Table 9 completeness: 61.2%

- algorithm: 100.0%
- certificate: 100.0%
- key: 45.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 80.0% of risk with 99.8 eng-weeks; 8 items left over

1. RootCA [mosip/resident-services] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [mosip/resident-services] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [mosip/resident-services] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [mosip/resident-services] tier=EXPOSED -> None  4.4 wk
5. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
6. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
7. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
8. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
9. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
10. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
11. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
12. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
13. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
14. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk
15. pkcs12-keystore [mosip/resident-services] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 95
- opengrep: 0
- dependency: 2
- certificate: 57
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
