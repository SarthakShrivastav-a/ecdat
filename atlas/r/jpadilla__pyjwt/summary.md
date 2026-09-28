# ECDAT scan: jpadilla__pyjwt

- id: `94c8c4f87648`  time: 2026-09-18T09:42:49.972381+00:00  duration: 14.2 s
- targets: 1  components: 1  libraries: 4  assets: 43
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 14
- SAFE: 28

## CERT-In Table 9 completeness: 63.1%

- algorithm: 74.1%
- protocol: 40.0%
- key: 48.0%
- certificate: 65.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 40.3 eng-weeks; 0 items left over

1. token:jwt [jpadilla/pyjwt] tier=MONITOR -> None  4.4 wk
2. token:jwt [jpadilla/pyjwt] tier=MONITOR -> None  4.4 wk
3. token:jwt [jpadilla/pyjwt] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [jpadilla/pyjwt] tier=MONITOR -> None  4.5 wk
5. token:jwt [jpadilla/pyjwt] tier=MONITOR -> None  4.5 wk
6. private-key:private-key [jpadilla/pyjwt] tier=MONITOR -> None  4.6 wk
7. RSA [jpadilla/pyjwt] tier=ACT_NOW -> ML-KEM-768  13.5 wk

## Collectors

- source: 134
- opengrep: 0
- dependency: 3
- certificate: 40
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
