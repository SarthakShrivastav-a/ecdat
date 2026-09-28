# ECDAT scan: mosip__id-repository

- id: `0fcbb9c0ac41`  time: 2026-09-18T08:22:00.801059+00:00  duration: 44.17 s
- targets: 1  components: 1  libraries: 3  assets: 39
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 2
- MONITOR: 27
- SAFE: 7

## CERT-In Table 9 completeness: 60.0%

- algorithm: 100.0%
- certificate: 100.0%
- key: 45.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 82.5% of risk with 101.4 eng-weeks; 7 items left over

1. RootCA [mosip/id-repository] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [mosip/id-repository] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [mosip/id-repository] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [mosip/id-repository] tier=EXPOSED -> None  4.4 wk
5. RSA [mosip/id-repository] tier=EXPOSED -> ML-KEM-768  9.8 wk
6. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
7. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
8. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
9. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
10. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
11. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
12. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
13. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
14. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk
15. pkcs12-keystore [mosip/id-repository] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 32
- opengrep: 0
- dependency: 1
- certificate: 66
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
