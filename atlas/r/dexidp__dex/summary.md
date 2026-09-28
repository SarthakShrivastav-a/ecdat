# ECDAT scan: dexidp__dex

- id: `fa2b8110faee`  time: 2026-09-18T08:22:45.224188+00:00  duration: 40.66 s
- targets: 1  components: 1  libraries: 5  assets: 71
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 3
- MONITOR: 13
- SAFE: 55

## CERT-In Table 9 completeness: 68.4%

- protocol: 46.7%
- algorithm: 78.9%
- certificate: 100.0%
- key: 55.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 66.2 eng-weeks; 0 items left over

1. TLS [dexidp/dex] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. TLS [dexidp/dex] tier=MONITOR -> X25519MLKEM768  1.9 wk
3. TLS [dexidp/dex] tier=MONITOR -> X25519MLKEM768  1.9 wk
4. TLS [dexidp/dex] tier=MONITOR -> X25519MLKEM768  1.9 wk
5. TLS [dexidp/dex] tier=MONITOR -> X25519MLKEM768  2.2 wk
6. TLS [dexidp/dex] tier=MONITOR -> X25519MLKEM768  2.3 wk
7. ECDH [dexidp/dex] tier=ACT_NOW -> X25519MLKEM768  6.6 wk
8. token:jwt [dexidp/dex] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [dexidp/dex] tier=MONITOR -> None  4.5 wk
10. key:generic-api-key [dexidp/dex] tier=MONITOR -> None  4.5 wk
11. ECDSA [dexidp/dex] tier=ACT_NOW -> ML-DSA-65  11.4 wk
12. AES [dexidp/dex] tier=MONITOR -> AES-256  7.0 wk
13. RSA [dexidp/dex] tier=ACT_NOW -> ML-KEM-768  15.7 wk

## Collectors

- source: 87
- opengrep: 0
- dependency: 3
- certificate: 148
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
