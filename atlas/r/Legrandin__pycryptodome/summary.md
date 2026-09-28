# ECDAT scan: Legrandin__pycryptodome

- id: `bede2524119c`  time: 2026-09-18T08:30:41.218663+00:00  duration: 135.3 s
- targets: 1  components: 1  libraries: 1  assets: 320
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 14
- MONITOR: 280
- SAFE: 26

## CERT-In Table 9 completeness: 55.1%

- algorithm: 91.8%
- key: 50.2%
- certificate: 87.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 10.0% of risk with 102.0 eng-weeks; 263 items left over

1. Client [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
2. Client [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
3. example.com [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
4. example.com [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
5. example.com [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
6. example.com [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
7. example.com [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
8. example.com [Legrandin/pycryptodome] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
9. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk
10. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk
11. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk
12. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk
13. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk
14. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk
15. private-key:ECDSA [Legrandin/pycryptodome] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 1765
- opengrep: 0
- dependency: 0
- certificate: 9128
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
