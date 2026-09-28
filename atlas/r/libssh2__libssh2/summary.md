# ECDAT scan: libssh2__libssh2

- id: `a8164abd2e92`  time: 2026-09-18T08:13:48.419537+00:00  duration: 32.78 s
- targets: 1  components: 1  libraries: 3  assets: 81
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 6
- MONITOR: 4
- SAFE: 71

## CERT-In Table 9 completeness: 55.2%

- algorithm: 89.1%
- protocol: 46.7%
- key: 46.2%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 97.0 eng-weeks; 0 items left over

1. TLS [libssh2/libssh2] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. Ed25519 [libssh2/libssh2] tier=ACT_NOW -> ML-DSA-65  9.0 wk
3. private-key:private-key [libssh2/libssh2] tier=MONITOR -> None  4.5 wk
4. key:generic-api-key [libssh2/libssh2] tier=MONITOR -> None  4.6 wk
5. key:generic-api-key [libssh2/libssh2] tier=MONITOR -> None  4.6 wk
6. MD5 [libssh2/libssh2] tier=ACT_NOW -> SHA-256  12.4 wk
7. ECDH [libssh2/libssh2] tier=ACT_NOW -> X25519MLKEM768  11.2 wk
8. SHA-1 [libssh2/libssh2] tier=ACT_NOW -> SHA-256  17.1 wk
9. ECDSA [libssh2/libssh2] tier=ACT_NOW -> ML-DSA-65  14.6 wk
10. RSA [libssh2/libssh2] tier=ACT_NOW -> ML-KEM-768  17.1 wk

## Collectors

- source: 278
- opengrep: 0
- dependency: 0
- certificate: 70
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
