# ECDAT scan: Sunbird-Lern__userorg-service

- id: `8b258db0ae62`  time: 2026-09-18T08:21:10.740264+00:00  duration: 50.02 s
- targets: 1  components: 1  libraries: 3  assets: 20
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 1
- MONITOR: 10
- SAFE: 9

## CERT-In Table 9 completeness: 60.3%

- algorithm: 95.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 54.7 eng-weeks; 0 items left over

1. key:generic-api-key [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.4 wk
2. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.4 wk
3. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.4 wk
4. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.4 wk
5. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.4 wk
6. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.4 wk
7. private-key:private-key [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.5 wk
8. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.5 wk
9. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.5 wk
10. token:jwt [Sunbird-Lern/userorg-service] tier=MONITOR -> None  4.8 wk
11. RSA [Sunbird-Lern/userorg-service] tier=ACT_NOW -> ML-KEM-768  10.0 wk

## Collectors

- source: 34
- opengrep: 0
- dependency: 1
- certificate: 70
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
