# ECDAT scan: IdentityPython__pysaml2

- id: `6f5645d9a69e`  time: 2026-09-18T08:16:47.767989+00:00  duration: 57.32 s
- targets: 1  components: 1  libraries: 6  assets: 80
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 3
- MONITOR: 22
- SAFE: 55

## CERT-In Table 9 completeness: 72.3%

- algorithm: 77.5%
- certificate: 95.0%
- key: 61.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 101.3 eng-weeks; 0 items left over

1. OU=IT,O=pysaml2 Demo Cert,L=Seattle,ST=WA,C=US [IdentityPython/pysaml2] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.1 wk
2. MD5 [IdentityPython/pysaml2] tier=ACT_NOW -> SHA-256  8.3 wk
3. private-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  3.6 wk
4. private-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  3.6 wk
5. private-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  3.6 wk
6. private-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  3.6 wk
7. key:generic-api-key [IdentityPython/pysaml2] tier=MONITOR -> None  4.4 wk
8. public-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  4.4 wk
9. public-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  4.4 wk
10. public-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  4.4 wk
11. public-key:RSA [IdentityPython/pysaml2] tier=MONITOR -> None  4.4 wk
12.  [IdentityPython/pysaml2] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  4.8 wk
13. SHA-1 [IdentityPython/pysaml2] tier=ACT_NOW -> SHA-256  17.1 wk
14. AES [IdentityPython/pysaml2] tier=MONITOR -> AES-256  7.4 wk
15. SHA-224 [IdentityPython/pysaml2] tier=MONITOR -> SHA-256  7.7 wk

## Collectors

- source: 31
- opengrep: 0
- dependency: 5
- certificate: 242
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
