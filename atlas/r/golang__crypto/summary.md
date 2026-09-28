# ECDAT scan: golang__crypto

- id: `9d16f8dbeca6`  time: 2026-09-18T08:12:03.852130+00:00  duration: 38.04 s
- targets: 1  components: 1  libraries: 5  assets: 169
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 11
- MONITOR: 122
- SAFE: 36

## CERT-In Table 9 completeness: 62.1%

- algorithm: 84.3%
- protocol: 60.0%
- key: 44.8%
- certificate: 59.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 26.5% of risk with 103.3 eng-weeks; 95 items left over

1. TLS [golang/crypto] tier=MONITOR -> X25519MLKEM768  2.2 wk
2. RC4 [golang/crypto] tier=ACT_NOW -> AES-256-GCM  6.6 wk
3.  [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
4. AC RAIZ FNMT-RCM SERVIDORES SEGUROS [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
5. ACCVRAIZ1 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
6. ANF Secure Server Root CA [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
7. Actalis Authentication Root CA [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
8. Amazon Root CA 1 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
9. Amazon Root CA 2 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
10. Amazon Root CA 3 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
11. Amazon Root CA 4 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
12. Atos TrustedRoot Root CA ECC TLS 2021 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
13. Atos TrustedRoot Root CA RSA TLS 2021 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
14. Autoridad de Certificacion Firmaprofesional CIF A62634068 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
15. BJCA Global Root CA1 [golang/crypto] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk

## Collectors

- source: 528
- opengrep: 0
- dependency: 2
- certificate: 943
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
