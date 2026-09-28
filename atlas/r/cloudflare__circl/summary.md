# ECDAT scan: cloudflare__circl

- id: `c29113001196`  time: 2026-09-18T08:58:18.351412+00:00  duration: 29.34 s
- targets: 1  components: 1  libraries: 6  assets: 24
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 4
- SAFE: 19

## CERT-In Table 9 completeness: 79.2%

- algorithm: 79.2%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 19.8 eng-weeks; 0 items left over

1. ECDH [cloudflare/circl] tier=ACT_NOW -> X25519MLKEM768  11.8 wk
2. AES [cloudflare/circl] tier=MONITOR -> AES-256  8.0 wk

## Collectors

- source: 977
- opengrep: 0
- dependency: 3
- certificate: 0
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
