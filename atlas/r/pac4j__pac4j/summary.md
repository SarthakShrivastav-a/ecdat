# ECDAT scan: pac4j__pac4j

- id: `a9c288c5f4c9`  time: 2026-09-18T08:36:50.585225+00:00  duration: 45.95 s
- targets: 1  components: 1  libraries: 9  assets: 49
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 18
- SAFE: 29

## CERT-In Table 9 completeness: 63.4%

- algorithm: 70.9%
- protocol: 60.0%
- key: 45.3%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 61.8 eng-weeks; 0 items left over

1. java-keystore [pac4j/pac4j] tier=MONITOR -> None  3.6 wk
2. MD5 [pac4j/pac4j] tier=ACT_NOW -> SHA-256  10.3 wk
3. key:generic-api-key [pac4j/pac4j] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [pac4j/pac4j] tier=MONITOR -> None  4.4 wk
5. private-key:private-key [pac4j/pac4j] tier=MONITOR -> None  4.4 wk
6. token:jwt [pac4j/pac4j] tier=MONITOR -> None  4.4 wk
7. unknown:curl-auth-header [pac4j/pac4j] tier=MONITOR -> None  4.4 wk
8. unknown:curl-auth-header [pac4j/pac4j] tier=MONITOR -> None  4.5 wk
9. key:generic-api-key [pac4j/pac4j] tier=MONITOR -> None  4.6 wk
10. RSA [pac4j/pac4j] tier=ACT_NOW -> ML-KEM-768  16.8 wk

## Collectors

- source: 161
- opengrep: 0
- dependency: 6
- certificate: 29
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
