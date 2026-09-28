# ECDAT scan: pyca__cryptography

- id: `428f70f74a02`  time: 2026-09-18T08:38:27.263406+00:00  duration: 79.58 s
- targets: 1  components: 1  libraries: 11  assets: 1097
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 42
- MONITOR: 1031
- SAFE: 24

## CERT-In Table 9 completeness: 83.5%

- algorithm: 91.3%
- key: 67.5%
- certificate: 99.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 6.0% of risk with 103.4 eng-weeks; 1031 items left over

1. VPS1 [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. leaf [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. leaf [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. leaf [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. leaf [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
6. leaf [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. DSA CA [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
8. Invalid DSA Signature EE Certificate Test6 [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
9. Valid DSA Signatures EE Certificate Test4 [pyca/cryptography] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
10. private-key:DH [pyca/cryptography] tier=ACT_NOW -> None  3.6 wk
11. private-key:DSA [pyca/cryptography] tier=ACT_NOW -> None  3.6 wk
12. private-key:DSA [pyca/cryptography] tier=ACT_NOW -> None  3.6 wk
13. private-key:DSA [pyca/cryptography] tier=ACT_NOW -> None  3.6 wk
14. private-key:DSA [pyca/cryptography] tier=ACT_NOW -> None  3.6 wk
15. private-key:DSA [pyca/cryptography] tier=ACT_NOW -> None  3.6 wk

## Collectors

- source: 3352
- opengrep: 0
- dependency: 6
- certificate: 3520
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
