# ECDAT scan: stripe__stripe-python

- id: `1a7762b9ca65`  time: 2026-09-18T08:29:14.317728+00:00  duration: 72.1 s
- targets: 1  components: 1  libraries: 3  assets: 161
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 5
- MONITOR: 150
- SAFE: 6

## CERT-In Table 9 completeness: 97.8%

- protocol: 40.0%
- algorithm: 100.0%
- certificate: 99.5%
- key: 46.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 29.3% of risk with 103.4 eng-weeks; 108 items left over

1. AC RAIZ FNMT-RCM SERVIDORES SEGUROS [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. ACCVRAIZ1 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. ANF Secure Server Root CA [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. Actalis Authentication Root CA [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. AffirmTrust Commercial [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
6. AffirmTrust Networking [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. AffirmTrust Premium [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. AffirmTrust Premium ECC [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. Amazon Root CA 1 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
10. Amazon Root CA 2 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
11. Amazon Root CA 3 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
12. Amazon Root CA 4 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
13. Atos TrustedRoot 2011 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
14. Atos TrustedRoot Root CA ECC TLS 2021 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
15. Atos TrustedRoot Root CA RSA TLS 2021 [stripe/stripe-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk

## Collectors

- source: 4
- opengrep: 0
- dependency: 3
- certificate: 1301
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
