# ECDAT scan: go-acme__lego

- id: `74ac070f5fdd`  time: 2026-09-18T08:18:34.991264+00:00  duration: 93.01 s
- targets: 1  components: 1  libraries: 5  assets: 96
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 7
- MONITOR: 39
- SAFE: 50

## CERT-In Table 9 completeness: 58.0%

- protocol: 40.0%
- algorithm: 79.9%
- certificate: 81.0%
- key: 46.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 52.0% of risk with 100.2 eng-weeks; 22 items left over

1. TLS [go-acme/lego] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. O=Acme Co [go-acme/lego] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. SHA-1 [go-acme/lego] tier=ACT_NOW -> SHA-256  8.5 wk
4. private-key:RSA [go-acme/lego] tier=MONITOR -> None  3.6 wk
5. private-key:unknown [go-acme/lego] tier=MONITOR -> None  3.6 wk
6. MD5 [go-acme/lego] tier=ACT_NOW -> SHA-256  9.2 wk
7. RSA [go-acme/lego] tier=ACT_NOW -> ML-KEM-768  7.5 wk
8. RSA [go-acme/lego] tier=ACT_NOW -> ML-KEM-768  7.5 wk
9.  [go-acme/lego] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.8 wk
10. RSA [go-acme/lego] tier=ACT_NOW -> ML-KEM-768  8.4 wk
11. key:generic-api-key [go-acme/lego] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [go-acme/lego] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [go-acme/lego] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [go-acme/lego] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [go-acme/lego] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 121
- opengrep: 0
- dependency: 3
- certificate: 190
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
