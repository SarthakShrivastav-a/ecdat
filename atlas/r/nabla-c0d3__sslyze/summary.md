# ECDAT scan: nabla-c0d3__sslyze

- id: `6800c81560ea`  time: 2026-09-18T08:18:06.228959+00:00  duration: 39.85 s
- targets: 1  components: 1  libraries: 3  assets: 442
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 14
- MONITOR: 387
- SAFE: 41

## CERT-In Table 9 completeness: 96.3%

- algorithm: 84.3%
- protocol: 60.0%
- certificate: 99.8%
- key: 55.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 13.5% of risk with 103.4 eng-weeks; 350 items left over

1. OU=Class 3 Public Primary Certification Authority,O=VeriSign\, Inc.,C=US [nabla-c0d3/sslyze] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. OU=FNMT Clase 2 CA,O=FNMT,C=ES [nabla-c0d3/sslyze] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. OU=VeriSign Trust Network,OU=(c) 1998 VeriSign\, Inc. - For authorized use only,OU=Class 2 Public Primary Certification Authority - G2,O=VeriSign\, Inc.,C=US [nabla-c0d3/sslyze] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. OU=VeriSign Trust Network,OU=(c) 1998 VeriSign\, Inc. - For authorized use only,OU=Class 3 Public Primary Certification Authority - G2,O=VeriSign\, Inc.,C=US [nabla-c0d3/sslyze] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. Thawte Premium Server CA [nabla-c0d3/sslyze] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
6. Thawte Timestamping CA [nabla-c0d3/sslyze] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. A-Trust-Root-07 [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. A-Trust-Root-09 [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. AC RAIZ FNMT-RCM G2 [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
10. ACA ROOT [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
11. ANCERT Certificados CGN V2 [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
12. ANCERT Certificados Notariales V2 [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
13. ANF Global Root CA [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
14. AddTrust Class 1 CA Root [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
15. AffirmTrust 4K TLS Root CA - 2022 [nabla-c0d3/sslyze] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk

## Collectors

- source: 81
- opengrep: 0
- dependency: 1
- certificate: 8510
- binary: 57

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
