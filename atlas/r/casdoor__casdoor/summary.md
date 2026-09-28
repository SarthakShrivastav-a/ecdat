# ECDAT scan: casdoor__casdoor

- id: `fce72553c165`  time: 2026-09-18T08:32:47.873340+00:00  duration: 69.25 s
- targets: 1  components: 1  libraries: 12  assets: 46
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 8
- MONITOR: 21
- SAFE: 17

## CERT-In Table 9 completeness: 65.5%

- protocol: 50.0%
- algorithm: 73.3%
- key: 44.3%
- certificate: 100.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 86.4% of risk with 100.7 eng-weeks; 2 items left over

1. TLS [casdoor/casdoor] tier=ACT_NOW -> X25519MLKEM768  2.2 wk
2. TLS [casdoor/casdoor] tier=MONITOR -> X25519MLKEM768  1.9 wk
3. TLS [casdoor/casdoor] tier=MONITOR -> X25519MLKEM768  2.0 wk
4. Casdoor Cert [casdoor/casdoor] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. TLS [casdoor/casdoor] tier=MONITOR -> X25519MLKEM768  2.2 wk
6. DES [casdoor/casdoor] tier=ACT_NOW -> AES-256-GCM  7.1 wk
7. SHA-1 [casdoor/casdoor] tier=ACT_NOW -> SHA-256  8.8 wk
8. X25519 [casdoor/casdoor] tier=ACT_NOW -> X25519MLKEM768  7.1 wk
9. ECDH [casdoor/casdoor] tier=ACT_NOW -> X25519MLKEM768  7.2 wk
10. private-key:unknown [casdoor/casdoor] tier=MONITOR -> None  3.6 wk
11. key:generic-api-key [casdoor/casdoor] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [casdoor/casdoor] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [casdoor/casdoor] tier=MONITOR -> None  4.4 wk
14. key:generic-api-key [casdoor/casdoor] tier=MONITOR -> None  4.4 wk
15. private-key:private-key [casdoor/casdoor] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 87
- opengrep: 0
- dependency: 10
- certificate: 24
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
