# ECDAT scan: mosip__id-authentication

- id: `bfa1d4434454`  time: 2026-09-18T09:02:51.726040+00:00  duration: 37.83 s
- targets: 1  components: 1  libraries: 5  assets: 47
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 3
- MONITOR: 27
- SAFE: 14

## CERT-In Table 9 completeness: 67.4%

- algorithm: 89.3%
- certificate: 100.0%
- key: 45.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 80.7% of risk with 103.5 eng-weeks; 8 items left over

1. RootCA [mosip/id-authentication] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [mosip/id-authentication] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [mosip/id-authentication] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [mosip/id-authentication] tier=EXPOSED -> None  4.4 wk
5. SHA-1 [mosip/id-authentication] tier=ACT_NOW -> SHA-256  8.0 wk
6. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
7. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
8. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
9. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
10. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
11. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
12. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
13. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
14. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk
15. pkcs12-keystore [mosip/id-authentication] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 93
- opengrep: 0
- dependency: 2
- certificate: 83
- binary: 3

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
