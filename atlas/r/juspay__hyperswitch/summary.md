# ECDAT scan: juspay__hyperswitch

- id: `850c247b218d`  time: 2026-09-18T09:19:43.871232+00:00  duration: 203.52 s
- targets: 1  components: 1  libraries: 10  assets: 46
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 7
- MONITOR: 24
- SAFE: 15

## CERT-In Table 9 completeness: 63.5%

- algorithm: 80.1%
- key: 44.3%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 72.3% of risk with 103.0 eng-weeks; 4 items left over

1. DES [juspay/hyperswitch] tier=ACT_NOW -> AES-256-GCM  9.5 wk
2. ECDH [juspay/hyperswitch] tier=ACT_NOW -> X25519MLKEM768  8.1 wk
3. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
4. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
5. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
6. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
7. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
8. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
10. unknown:curl-auth-header [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
11. unknown:curl-auth-user [juspay/hyperswitch] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.5 wk
13. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.5 wk
14. key:generic-api-key [juspay/hyperswitch] tier=MONITOR -> None  4.5 wk
15. private-key:RSA [juspay/hyperswitch] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 554
- opengrep: 0
- dependency: 10
- certificate: 48
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
