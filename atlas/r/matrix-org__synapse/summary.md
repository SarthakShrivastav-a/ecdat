# ECDAT scan: matrix-org__synapse

- id: `bff8f114aac3`  time: 2026-09-18T09:14:45.678406+00:00  duration: 56.25 s
- targets: 1  components: 1  libraries: 9  assets: 47
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 18
- SAFE: 27

## CERT-In Table 9 completeness: 63.4%

- protocol: 40.0%
- algorithm: 73.8%
- key: 49.6%
- certificate: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 64.7 eng-weeks; 0 items left over

1. TLS [matrix-org/synapse] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. SHA-1 [matrix-org/synapse] tier=ACT_NOW -> SHA-256  8.3 wk
3. key:generic-api-key [matrix-org/synapse] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [matrix-org/synapse] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [matrix-org/synapse] tier=MONITOR -> None  4.4 wk
6. private-key:private-key [matrix-org/synapse] tier=MONITOR -> None  4.4 wk
7. token:jwt [matrix-org/synapse] tier=MONITOR -> None  4.4 wk
8. unknown:curl-auth-header [matrix-org/synapse] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [matrix-org/synapse] tier=MONITOR -> None  4.5 wk
10. key:generic-api-key [matrix-org/synapse] tier=MONITOR -> None  4.5 wk
11. key:generic-api-key [matrix-org/synapse] tier=MONITOR -> None  4.5 wk
12. RSA [matrix-org/synapse] tier=ACT_NOW -> ML-KEM-768  14.6 wk

## Collectors

- source: 31
- opengrep: 0
- dependency: 8
- certificate: 57
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
