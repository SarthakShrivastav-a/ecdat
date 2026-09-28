# ECDAT scan: panva__jose

- id: `6de11ddf5d78`  time: 2026-09-18T08:15:54.717255+00:00  duration: 37.85 s
- targets: 1  components: 1  libraries: 1  assets: 23
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 12
- SAFE: 11

## CERT-In Table 9 completeness: 69.5%

- protocol: 40.0%
- algorithm: 96.4%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 51.4 eng-weeks; 0 items left over

1. TLS [panva/jose] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. private-key:private-key [panva/jose] tier=MONITOR -> None  4.4 wk
3. private-key:private-key [panva/jose] tier=MONITOR -> None  4.4 wk
4. private-key:private-key [panva/jose] tier=MONITOR -> None  4.4 wk
5. private-key:private-key [panva/jose] tier=MONITOR -> None  4.4 wk
6. token:jwt [panva/jose] tier=MONITOR -> None  4.4 wk
7. token:jwt [panva/jose] tier=MONITOR -> None  4.4 wk
8. private-key:private-key [panva/jose] tier=MONITOR -> None  4.5 wk
9. token:jwt [panva/jose] tier=MONITOR -> None  4.5 wk
10. token:jwt [panva/jose] tier=MONITOR -> None  4.5 wk
11. key:generic-api-key [panva/jose] tier=MONITOR -> None  4.8 wk
12. private-key:private-key [panva/jose] tier=MONITOR -> None  4.8 wk

## Collectors

- source: 76
- opengrep: 0
- dependency: 1
- certificate: 44
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
