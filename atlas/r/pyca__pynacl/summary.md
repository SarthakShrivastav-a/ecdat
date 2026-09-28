# ECDAT scan: pyca__pynacl

- id: `1cb03fa87afc`  time: 2026-09-18T08:44:22.966412+00:00  duration: 33.96 s
- targets: 1  components: 1  libraries: 3  assets: 23
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 5
- SAFE: 16

## CERT-In Table 9 completeness: 54.7%

- algorithm: 97.1%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 50.0 eng-weeks; 0 items left over

1. key:generic-api-key [pyca/pynacl] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [pyca/pynacl] tier=MONITOR -> None  4.5 wk
3. key:generic-api-key [pyca/pynacl] tier=MONITOR -> None  4.5 wk
4. key:generic-api-key [pyca/pynacl] tier=MONITOR -> None  4.5 wk
5. key:generic-api-key [pyca/pynacl] tier=MONITOR -> None  4.5 wk
6. Ed25519 [pyca/pynacl] tier=ACT_NOW -> ML-DSA-65  11.1 wk
7. X25519 [pyca/pynacl] tier=ACT_NOW -> X25519MLKEM768  16.5 wk

## Collectors

- source: 191
- opengrep: 0
- dependency: 1
- certificate: 114
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
