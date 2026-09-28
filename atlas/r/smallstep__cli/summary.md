# ECDAT scan: smallstep__cli

- id: `60d45a3be250`  time: 2026-09-18T08:13:11.353614+00:00  duration: 31.43 s
- targets: 1  components: 1  libraries: 5  assets: 56
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 11
- SAFE: 45

## CERT-In Table 9 completeness: 68.6%

- protocol: 60.0%
- algorithm: 82.3%
- key: 56.5%
- certificate: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 24.3 eng-weeks; 0 items left over

1. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
2. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
3. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
4. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
5. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
6. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
7. TLS [smallstep/cli] tier=MONITOR -> X25519MLKEM768  2.2 wk
8. key:generic-api-key [smallstep/cli] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [smallstep/cli] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 113
- opengrep: 0
- dependency: 3
- certificate: 73
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
