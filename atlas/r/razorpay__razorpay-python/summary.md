# ECDAT scan: razorpay__razorpay-python

- id: `c134a505a1df`  time: 2026-09-18T09:42:18.104044+00:00  duration: 16.66 s
- targets: 1  components: 1  libraries: 1  assets: 175
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 8
- MONITOR: 164
- SAFE: 3

## CERT-In Table 9 completeness: 96.7%

- algorithm: 100.0%
- certificate: 99.6%
- key: 44.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 26.6% of risk with 103.4 eng-weeks; 125 items left over

1. OU=Equifax Secure Certificate Authority,O=Equifax,C=US [razorpay/razorpay-python] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. A-Trust-nQual-03 [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. AAA Certificate Services [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. ACCVRAIZ1 [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. ACEDICOM Root [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
6. Actalis Authentication Root CA [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. AddTrust Class 1 CA Root [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. AddTrust External CA Root [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. AddTrust Public CA Root [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
10. AddTrust Qualified CA Root [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
11. AffirmTrust Commercial [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
12. AffirmTrust Networking [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
13. AffirmTrust Premium [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
14. AffirmTrust Premium ECC [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
15. Atos TrustedRoot 2011 [razorpay/razorpay-python] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk

## Collectors

- source: 1
- opengrep: 0
- dependency: 1
- certificate: 1404
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
