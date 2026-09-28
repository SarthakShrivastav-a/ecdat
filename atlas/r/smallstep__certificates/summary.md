# ECDAT scan: smallstep__certificates

- id: `a07db741ae2a`  time: 2026-09-18T08:31:31.435748+00:00  duration: 39.56 s
- targets: 1  components: 1  libraries: 7  assets: 209
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 37
- MONITOR: 30
- SAFE: 142

## CERT-In Table 9 completeness: 67.1%

- algorithm: 81.1%
- protocol: 51.6%
- certificate: 98.9%
- key: 45.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 80.7% of risk with 102.7 eng-weeks; 19 items left over

1. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
6. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
10. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
11. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
12. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
13. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
14. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
15. O=Amazon Web Services LLC,L=Seattle,ST=Washington State,C=US [smallstep/certificates] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk

## Collectors

- source: 339
- opengrep: 0
- dependency: 5
- certificate: 798
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
