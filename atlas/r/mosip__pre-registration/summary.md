# ECDAT scan: mosip__pre-registration

- id: `c4565882f3ea`  time: 2026-09-18T09:03:53.045316+00:00  duration: 22.81 s
- targets: 1  components: 1  libraries: 4  assets: 9
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 7
- SAFE: 1

## CERT-In Table 9 completeness: 49.2%

- algorithm: 100.0%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 39.1 eng-weeks; 0 items left over

1. RSA [mosip/pre-registration] tier=EXPOSED -> ML-KEM-768  7.7 wk
2. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.5 wk
5. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.5 wk
6. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.5 wk
7. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.5 wk
8. key:generic-api-key [mosip/pre-registration] tier=MONITOR -> None  4.6 wk

## Collectors

- source: 40
- opengrep: 0
- dependency: 1
- certificate: 24
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
