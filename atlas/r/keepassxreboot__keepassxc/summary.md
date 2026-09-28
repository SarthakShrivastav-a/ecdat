# ECDAT scan: keepassxreboot__keepassxc

- id: `29fdfed380b8`  time: 2026-09-18T08:38:11.114926+00:00  duration: 74.18 s
- targets: 1  components: 1  libraries: 3  assets: 35
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 1
- ACT_NOW: 0
- MONITOR: 5
- SAFE: 29

## CERT-In Table 9 completeness: 58.8%

- algorithm: 73.8%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 17.2 eng-weeks; 0 items left over

1. X25519 [keepassxreboot/keepassxc] tier=EXPOSED -> X25519MLKEM768  8.4 wk
2. private-key:private-key [keepassxreboot/keepassxc] tier=MONITOR -> None  4.4 wk
3. private-key:private-key [keepassxreboot/keepassxc] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 45
- opengrep: 0
- dependency: 2
- certificate: 38
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
