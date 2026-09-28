# ECDAT scan: WireGuard__wireguard-go

- id: `0431de916505`  time: 2026-09-18T09:44:31.306672+00:00  duration: 17.59 s
- targets: 1  components: 1  libraries: 3  assets: 15
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 7
- SAFE: 8

## CERT-In Table 9 completeness: 60.9%

- algorithm: 65.5%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 13.2 eng-weeks; 0 items left over

1. key:generic-api-key [WireGuard/wireguard-go] tier=MONITOR -> None  4.4 wk
2. key:generic-api-key [WireGuard/wireguard-go] tier=MONITOR -> None  4.4 wk
3. key:generic-api-key [WireGuard/wireguard-go] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 20
- opengrep: 0
- dependency: 2
- certificate: 3
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
