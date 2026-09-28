# ECDAT scan: Mbed-TLS__mbedtls

- id: `0eea48a1d847`  time: 2026-09-18T08:42:04.408522+00:00  duration: 25.49 s
- targets: 1  components: 1  libraries: 3  assets: 22
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 3
- MONITOR: 3
- SAFE: 16

## CERT-In Table 9 completeness: 84.0%

- algorithm: 91.3%
- protocol: 60.0%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 60.2 eng-weeks; 0 items left over

1. TLS [Mbed-TLS/mbedtls] tier=MONITOR -> X25519MLKEM768  2.9 wk
2. TLS [Mbed-TLS/mbedtls] tier=MONITOR -> X25519MLKEM768  2.9 wk
3. MD5 [Mbed-TLS/mbedtls] tier=ACT_NOW -> SHA-256  14.0 wk
4. SHA-1 [Mbed-TLS/mbedtls] tier=ACT_NOW -> SHA-256  14.7 wk
5. RSA [Mbed-TLS/mbedtls] tier=ACT_NOW -> ML-KEM-768  14.7 wk
6. AES [Mbed-TLS/mbedtls] tier=MONITOR -> AES-256  11.0 wk

## Collectors

- source: 2684
- opengrep: 0
- dependency: 2
- certificate: 5
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
