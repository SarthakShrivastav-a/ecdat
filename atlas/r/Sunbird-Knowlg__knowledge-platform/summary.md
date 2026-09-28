# ECDAT scan: Sunbird-Knowlg__knowledge-platform

- id: `fe7084c90948`  time: 2026-09-18T08:34:29.691437+00:00  duration: 54.14 s
- targets: 1  components: 1  libraries: 2  assets: 32
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 17
- SAFE: 13

## CERT-In Table 9 completeness: 47.4%

- protocol: 40.0%
- algorithm: 95.2%
- key: 42.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 78.0 eng-weeks; 0 items left over

1. TLS [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. TLS [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> X25519MLKEM768  1.9 wk
3. TLS [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> X25519MLKEM768  1.9 wk
4. TLS [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> X25519MLKEM768  1.9 wk
5. TLS [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> X25519MLKEM768  1.9 wk
6. MD5 [Sunbird-Knowlg/knowledge-platform] tier=ACT_NOW -> SHA-256  7.5 wk
7. DES [Sunbird-Knowlg/knowledge-platform] tier=ACT_NOW -> AES-256-GCM  7.6 wk
8. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
9. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
11. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
12. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
13. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
14. private-key:private-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [Sunbird-Knowlg/knowledge-platform] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 14
- opengrep: 0
- dependency: 1
- certificate: 38
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
