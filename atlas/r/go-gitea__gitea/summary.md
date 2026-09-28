# ECDAT scan: go-gitea__gitea

- id: `8ba31d1b02cd`  time: 2026-09-18T09:10:05.192962+00:00  duration: 138.59 s
- targets: 1  components: 1  libraries: 8  assets: 57
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 7
- MONITOR: 11
- SAFE: 39

## CERT-In Table 9 completeness: 60.7%

- protocol: 53.3%
- algorithm: 79.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 91.8% of risk with 102.6 eng-weeks; 1 items left over

1. TLS [go-gitea/gitea] tier=ACT_NOW -> X25519MLKEM768  2.3 wk
2. TLS [go-gitea/gitea] tier=MONITOR -> X25519MLKEM768  1.9 wk
3. X25519 [go-gitea/gitea] tier=ACT_NOW -> X25519MLKEM768  7.1 wk
4. Ed25519 [go-gitea/gitea] tier=ACT_NOW -> ML-DSA-65  8.8 wk
5. key:generic-api-key [go-gitea/gitea] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [go-gitea/gitea] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [go-gitea/gitea] tier=MONITOR -> None  4.6 wk
8. key:generic-api-key [go-gitea/gitea] tier=MONITOR -> None  4.6 wk
9. key:generic-api-key [go-gitea/gitea] tier=MONITOR -> None  4.6 wk
10. key:generic-api-key [go-gitea/gitea] tier=MONITOR -> None  4.8 wk
11. MD5 [go-gitea/gitea] tier=ACT_NOW -> SHA-256  14.1 wk
12. SHA-1 [go-gitea/gitea] tier=ACT_NOW -> SHA-256  14.1 wk
13. ECDSA [go-gitea/gitea] tier=ACT_NOW -> ML-DSA-65  11.6 wk
14. ECDH [go-gitea/gitea] tier=MONITOR -> X25519MLKEM768  7.3 wk
15. AES [go-gitea/gitea] tier=MONITOR -> AES-256  8.0 wk

## Collectors

- source: 263
- opengrep: 0
- dependency: 6
- certificate: 67
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
