# ECDAT scan: ory__kratos

- id: `0be7d44bb664`  time: 2026-09-18T08:40:13.802611+00:00  duration: 112.67 s
- targets: 1  components: 1  libraries: 7  assets: 66
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 6
- MONITOR: 27
- SAFE: 33

## CERT-In Table 9 completeness: 57.6%

- algorithm: 81.5%
- protocol: 42.7%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 85.1% of risk with 103.7 eng-weeks; 3 items left over

1. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
3. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
4. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
5. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
6. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
7. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  1.9 wk
8. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
9. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
10. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
11. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
12. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
13. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
14. TLS [ory/kratos] tier=MONITOR -> X25519MLKEM768  2.2 wk
15. RSA [ory/kratos] tier=ACT_NOW -> ML-KEM-768  7.5 wk

## Collectors

- source: 158
- opengrep: 0
- dependency: 5
- certificate: 46
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
