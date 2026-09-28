# ECDAT scan: Sunbird-RC__sunbird-rc-core

- id: `a5ee2edb8873`  time: 2026-09-18T08:41:35.747794+00:00  duration: 48.34 s
- targets: 1  components: 1  libraries: 18  assets: 41
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 5
- ACT_NOW: 10
- MONITOR: 15
- SAFE: 11

## CERT-In Table 9 completeness: 65.9%

- algorithm: 79.4%
- protocol: 53.3%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 73.5% of risk with 103.3 eng-weeks; 10 items left over

1. TLS [Sunbird-RC/sunbird-rc-core] tier=EXPOSED -> X25519MLKEM768  2.2 wk
2. TLS [Sunbird-RC/sunbird-rc-core] tier=EXPOSED -> X25519MLKEM768  2.2 wk
3. TLS [Sunbird-RC/sunbird-rc-core] tier=EXPOSED -> X25519MLKEM768  2.7 wk
4. 3DES [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> AES-256-GCM  8.0 wk
5. MD5 [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> SHA-256  8.0 wk
6. RC4 [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> AES-256-GCM  8.0 wk
7. SHA-1 [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> SHA-256  8.0 wk
8. ECDH [Sunbird-RC/sunbird-rc-core] tier=EXPOSED -> X25519MLKEM768  10.0 wk
9. Blowfish [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> AES-256-GCM  8.5 wk
10. DES [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> AES-256-GCM  8.5 wk
11. AES [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> AES-256  8.0 wk
12. DSA [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> ML-DSA-65  8.0 wk
13. Ed25519 [Sunbird-RC/sunbird-rc-core] tier=ACT_NOW -> ML-DSA-65  8.0 wk
14. key:generic-api-key [Sunbird-RC/sunbird-rc-core] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [Sunbird-RC/sunbird-rc-core] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 114
- opengrep: 0
- dependency: 12
- certificate: 26
- binary: 27

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
