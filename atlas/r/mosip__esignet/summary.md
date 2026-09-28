# ECDAT scan: mosip__esignet

- id: `edfdc696e0b1`  time: 2026-09-18T08:27:56.917602+00:00  duration: 66.67 s
- targets: 1  components: 1  libraries: 8  assets: 30
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 3
- ACT_NOW: 3
- MONITOR: 14
- SAFE: 10

## CERT-In Table 9 completeness: 67.4%

- algorithm: 72.3%
- certificate: 100.0%
- key: 47.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 73.7 eng-weeks; 0 items left over

1. RootCA [mosip/esignet] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. RootCAFTM [mosip/esignet] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. public-key:RSA [mosip/esignet] tier=EXPOSED -> None  4.4 wk
4. public-key:RSA [mosip/esignet] tier=EXPOSED -> None  4.4 wk
5. SHA-1 [mosip/esignet] tier=ACT_NOW -> SHA-256  8.0 wk
6. key:generic-api-key [mosip/esignet] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [mosip/esignet] tier=MONITOR -> None  4.4 wk
8. key:generic-api-key [mosip/esignet] tier=MONITOR -> None  4.4 wk
9. private-key:private-key [mosip/esignet] tier=MONITOR -> None  4.4 wk
10. unknown:kubernetes-secret-yaml [mosip/esignet] tier=MONITOR -> None  4.4 wk
11. private-key:private-key [mosip/esignet] tier=MONITOR -> None  4.5 wk
12. token:jwt [mosip/esignet] tier=MONITOR -> None  4.5 wk
13. token:jwt [mosip/esignet] tier=MONITOR -> None  4.7 wk
14. RSA [mosip/esignet] tier=EXPOSED -> ML-KEM-768  16.8 wk

## Collectors

- source: 128
- opengrep: 0
- dependency: 5
- certificate: 41
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
