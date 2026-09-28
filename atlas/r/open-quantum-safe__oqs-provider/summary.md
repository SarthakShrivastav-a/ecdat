# ECDAT scan: open-quantum-safe__oqs-provider

- id: `561077d5ff8b`  time: 2026-09-18T09:43:10.798891+00:00  duration: 18.71 s
- targets: 1  components: 1  libraries: 2  assets: 19
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 2
- SAFE: 13

## CERT-In Table 9 completeness: 83.2%

- algorithm: 98.6%
- protocol: 60.0%
- certificate: 100.0%
- key: 57.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 41.8 eng-weeks; 0 items left over

1. TLS [open-quantum-safe/oqs-provider] tier=ACT_NOW -> X25519MLKEM768  3.2 wk
2. RSA [open-quantum-safe/oqs-provider] tier=ACT_NOW -> ML-KEM-768  8.3 wk
3. key:generic-api-key [open-quantum-safe/oqs-provider] tier=MONITOR -> None  4.4 wk
4. unknown:curl-auth-header [open-quantum-safe/oqs-provider] tier=MONITOR -> None  4.4 wk
5. X25519 [open-quantum-safe/oqs-provider] tier=ACT_NOW -> X25519MLKEM768  8.9 wk
6. RSA [open-quantum-safe/oqs-provider] tier=ACT_NOW -> ML-KEM-768  12.6 wk

## Collectors

- source: 364
- opengrep: 0
- dependency: 0
- certificate: 14
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
