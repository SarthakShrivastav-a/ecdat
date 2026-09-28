# ECDAT scan: tink-crypto__tink-java

- id: `c398a9330d88`  time: 2026-09-18T08:24:18.065013+00:00  duration: 89.3 s
- targets: 1  components: 1  libraries: 3  assets: 24
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 5
- SAFE: 15

## CERT-In Table 9 completeness: 68.8%

- algorithm: 90.5%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 83.1 eng-weeks; 0 items left over

1. MD5 [tink-crypto/tink-java] tier=ACT_NOW -> SHA-256  7.7 wk
2. key:generic-api-key [tink-crypto/tink-java] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [tink-crypto/tink-java] tier=MONITOR -> None  4.5 wk
4. key:generic-api-key [tink-crypto/tink-java] tier=MONITOR -> None  4.5 wk
5. SHA-1 [tink-crypto/tink-java] tier=ACT_NOW -> SHA-256  13.2 wk
6. ECDSA [tink-crypto/tink-java] tier=ACT_NOW -> ML-DSA-65  15.8 wk
7. RSA [tink-crypto/tink-java] tier=ACT_NOW -> ML-KEM-768  15.8 wk
8. AES [tink-crypto/tink-java] tier=MONITOR -> AES-256  8.6 wk
9. AES [tink-crypto/tink-java] tier=MONITOR -> AES-256  8.6 wk

## Collectors

- source: 2399
- opengrep: 0
- dependency: 1
- certificate: 34
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
