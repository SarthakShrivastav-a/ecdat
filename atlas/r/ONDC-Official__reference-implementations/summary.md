# ECDAT scan: ONDC-Official__reference-implementations

- id: `ef129cc6cc51`  time: 2026-09-18T08:13:46.882964+00:00  duration: 87.45 s
- targets: 1  components: 1  libraries: 18  assets: 39
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 21
- SAFE: 14

## CERT-In Table 9 completeness: 61.5%

- algorithm: 68.9%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 103.7 eng-weeks; 0 items left over

1. RSA [ONDC-Official/reference-implementations] tier=ACT_NOW -> ML-KEM-768  8.4 wk
2. private-key:private-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.4 wk
3. private-key:private-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.5 wk
5. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.5 wk
6. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.5 wk
7. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.5 wk
8. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.5 wk
9. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.5 wk
10. key:generic-api-key [ONDC-Official/reference-implementations] tier=MONITOR -> None  4.6 wk
11. DH [ONDC-Official/reference-implementations] tier=ACT_NOW -> X25519MLKEM768  10.0 wk
12. X25519 [ONDC-Official/reference-implementations] tier=ACT_NOW -> X25519MLKEM768  13.7 wk
13. Ed25519 [ONDC-Official/reference-implementations] tier=ACT_NOW -> ML-DSA-65  15.4 wk
14. AES [ONDC-Official/reference-implementations] tier=MONITOR -> AES-256  15.8 wk

## Collectors

- source: 177
- opengrep: 0
- dependency: 12
- certificate: 21
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
