# ECDAT scan: ory__hydra

- id: `c5ef9eeddc5c`  time: 2026-09-18T08:41:53.492286+00:00  duration: 88.05 s
- targets: 1  components: 1  libraries: 11  assets: 488
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 8
- MONITOR: 445
- SAFE: 35

## CERT-In Table 9 completeness: 48.6%

- algorithm: 78.8%
- key: 43.9%
- certificate: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 5.6% of risk with 100.0 eng-weeks; 428 items left over

1. 3DES [ory/hydra] tier=ACT_NOW -> AES-256-GCM  8.0 wk
2. SHA-1 [ory/hydra] tier=ACT_NOW -> SHA-256  8.0 wk
3. RSA [ory/hydra] tier=ACT_NOW -> ML-KEM-768  8.4 wk
4. private-key:ECDSA [ory/hydra] tier=MONITOR -> None  3.6 wk
5. private-key:RSA [ory/hydra] tier=MONITOR -> None  3.6 wk
6. private-key:unknown [ory/hydra] tier=MONITOR -> None  3.6 wk
7. Ed25519 [ory/hydra] tier=ACT_NOW -> ML-DSA-65  8.0 wk
8. RSA [ory/hydra] tier=ACT_NOW -> ML-KEM-768  8.4 wk
9. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [ory/hydra] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 185
- opengrep: 0
- dependency: 9
- certificate: 2013
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
