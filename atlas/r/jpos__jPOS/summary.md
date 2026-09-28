# ECDAT scan: jpos__jPOS

- id: `a067c133fade`  time: 2026-09-18T08:35:59.588228+00:00  duration: 45.56 s
- targets: 1  components: 1  libraries: 4  assets: 13
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 3
- MONITOR: 3
- SAFE: 7

## CERT-In Table 9 completeness: 80.4%

- protocol: 60.0%
- algorithm: 91.1%
- key: 52.4%
- certificate: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 50.9 eng-weeks; 0 items left over

1. TLS [jpos/jPOS] tier=MONITOR -> X25519MLKEM768  2.2 wk
2. MD5 [jpos/jPOS] tier=ACT_NOW -> SHA-256  8.3 wk
3. private-key:private-key [jpos/jPOS] tier=MONITOR -> None  4.4 wk
4. DES [jpos/jPOS] tier=ACT_NOW -> AES-256-GCM  14.7 wk
5. SHA-1 [jpos/jPOS] tier=ACT_NOW -> SHA-256  14.7 wk
6. AES [jpos/jPOS] tier=MONITOR -> AES-256  6.6 wk

## Collectors

- source: 326
- opengrep: 0
- dependency: 1
- certificate: 7
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
