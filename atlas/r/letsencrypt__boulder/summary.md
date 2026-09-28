# ECDAT scan: letsencrypt__boulder

- id: `1f829022375d`  time: 2026-09-18T08:34:35.135289+00:00  duration: 137.04 s
- targets: 1  components: 1  libraries: 9  assets: 264
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 6
- MONITOR: 172
- SAFE: 86

## CERT-In Table 9 completeness: 64.5%

- protocol: 58.0%
- algorithm: 78.8%
- certificate: 65.2%
- key: 54.9%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 22.0% of risk with 101.5 eng-weeks; 131 items left over

1. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  1.9 wk
2. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.2 wk
3. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.2 wk
4. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.2 wk
5. test-dir [letsencrypt/boulder] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
6. test-file [letsencrypt/boulder] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
7. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.5 wk
8. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.5 wk
9. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.5 wk
10. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.5 wk
11. TLS [letsencrypt/boulder] tier=MONITOR -> X25519MLKEM768  2.6 wk
12.  [letsencrypt/boulder] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
13. AAA Certificate Services [letsencrypt/boulder] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
14. ANF Global Root CA [letsencrypt/boulder] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk
15. Actalis Authentication Root CA [letsencrypt/boulder] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.7 wk

## Collectors

- source: 1348
- opengrep: 0
- dependency: 6
- certificate: 1288
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
