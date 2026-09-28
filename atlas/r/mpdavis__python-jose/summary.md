# ECDAT scan: mpdavis__python-jose

- id: `0d1f61a424d5`  time: 2026-09-18T09:41:08.659845+00:00  duration: 14.4 s
- targets: 1  components: 1  libraries: 5  assets: 37
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 14
- SAFE: 21

## CERT-In Table 9 completeness: 65.8%

- algorithm: 73.1%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 34.9 eng-weeks; 0 items left over

1. key:generic-api-key [mpdavis/python-jose] tier=MONITOR -> None  4.4 wk
2. token:jwt [mpdavis/python-jose] tier=MONITOR -> None  4.4 wk
3. ECDSA [mpdavis/python-jose] tier=ACT_NOW -> ML-DSA-65  8.9 wk
4. RSA [mpdavis/python-jose] tier=ACT_NOW -> ML-KEM-768  9.6 wk
5. AES [mpdavis/python-jose] tier=MONITOR -> AES-256  7.6 wk

## Collectors

- source: 47
- opengrep: 0
- dependency: 4
- certificate: 33
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
