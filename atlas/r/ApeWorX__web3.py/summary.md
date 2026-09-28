# ECDAT scan: ApeWorX__web3.py

- id: `7b47febf408f`  time: 2026-09-18T08:26:37.333727+00:00  duration: 35.71 s
- targets: 1  components: 1  libraries: 2  assets: 7
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 3
- SAFE: 3

## CERT-In Table 9 completeness: 56.8%

- protocol: 40.0%
- algorithm: 92.8%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 18.5 eng-weeks; 0 items left over

1. TLS [ApeWorX/web3.py] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. MD5 [ApeWorX/web3.py] tier=ACT_NOW -> SHA-256  7.7 wk
3. key:generic-api-key [ApeWorX/web3.py] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [ApeWorX/web3.py] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 3
- opengrep: 0
- dependency: 2
- certificate: 7
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
