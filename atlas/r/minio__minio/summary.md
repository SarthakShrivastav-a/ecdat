# ECDAT scan: minio__minio

- id: `3fa78aa41001`  time: 2026-09-18T08:40:40.534879+00:00  duration: 48.17 s
- targets: 1  components: 1  libraries: 6  assets: 104
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 6
- MONITOR: 57
- SAFE: 41

## CERT-In Table 9 completeness: 53.1%

- algorithm: 78.9%
- protocol: 60.0%
- certificate: 65.0%
- key: 43.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 38.2% of risk with 99.5 eng-weeks; 37 items left over

1. root@play.min.io [minio/minio] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. TLS [minio/minio] tier=MONITOR -> X25519MLKEM768  2.2 wk
3. TLS [minio/minio] tier=MONITOR -> X25519MLKEM768  2.2 wk
4. TLS [minio/minio] tier=MONITOR -> X25519MLKEM768  2.2 wk
5. TLS [minio/minio] tier=MONITOR -> X25519MLKEM768  2.2 wk
6. X25519 [minio/minio] tier=ACT_NOW -> X25519MLKEM768  7.1 wk
7. private-key:Ed25519 [minio/minio] tier=MONITOR -> None  3.6 wk
8. ECDH [minio/minio] tier=ACT_NOW -> X25519MLKEM768  7.4 wk
9. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [minio/minio] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 360
- opengrep: 0
- dependency: 4
- certificate: 132
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
