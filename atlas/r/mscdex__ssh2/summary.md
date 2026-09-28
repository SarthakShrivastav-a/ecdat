# ECDAT scan: mscdex__ssh2

- id: `2927ed03aefd`  time: 2026-09-18T08:14:17.479466+00:00  duration: 26.95 s
- targets: 1  components: 1  libraries: 3  assets: 68
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 2
- SAFE: 62

## CERT-In Table 9 completeness: 55.7%

- algorithm: 93.4%
- certificate: 100.0%
- key: 45.8%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 49.7 eng-weeks; 0 items left over

1. RC4 [mscdex/ssh2] tier=ACT_NOW -> AES-256-GCM  9.5 wk
2. X25519 [mscdex/ssh2] tier=ACT_NOW -> X25519MLKEM768  7.7 wk
3. MD5 [mscdex/ssh2] tier=ACT_NOW -> SHA-256  9.8 wk
4. SHA-1 [mscdex/ssh2] tier=ACT_NOW -> SHA-256  9.9 wk
5. private-key:private-key [mscdex/ssh2] tier=MONITOR -> None  4.4 wk
6. AES-128 [mscdex/ssh2] tier=MONITOR -> AES-256  8.4 wk

## Collectors

- source: 55
- opengrep: 0
- dependency: 1
- certificate: 64
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
