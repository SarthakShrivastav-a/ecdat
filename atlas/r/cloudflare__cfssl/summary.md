# ECDAT scan: cloudflare__cfssl

- id: `bff33caf1f5d`  time: 2026-09-18T08:31:35.967793+00:00  duration: 92.45 s
- targets: 1  components: 1  libraries: 4  assets: 2127
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 14
- MONITOR: 221
- SAFE: 1892

## CERT-In Table 9 completeness: 95.4%

- algorithm: 87.5%
- protocol: 60.0%
- certificate: 99.9%
- key: 54.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 19.2% of risk with 102.6 eng-weeks; 193 items left over

1. DoD CLASS 3 Root CA [cloudflare/cfssl] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.5 wk
2. TLS [cloudflare/cfssl] tier=ACT_NOW -> X25519MLKEM768  2.6 wk
3. ECA Root CA [cloudflare/cfssl] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.9 wk
4. Equifax Secure Global eBusiness CA-1 [cloudflare/cfssl] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.6 wk
5. Equifax Secure eBusiness CA-1 [cloudflare/cfssl] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.6 wk
6. AlphaSSL CA - SHA256 - G2 [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. GlobalSign Extended Validation CA - SHA256 - G2 [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. GlobalSign Organization Validation CA - SHA256 - G2 [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. GlobeSSL CA [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
10. InCommon Server CA [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
11. SSL.com Free SSL CA [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
12. Symantec Class 3 ECC 256 bit Extended Validation CA [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
13. Trusted Secure Certificate Authority [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
14. test-dir [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
15. test-file [cloudflare/cfssl] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk

## Collectors

- source: 852
- opengrep: 0
- dependency: 2
- certificate: 14387
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
