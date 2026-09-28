# ECDAT scan: signalapp__libsignal

- id: `3c79036a17ac`  time: 2026-09-18T08:20:14.293496+00:00  duration: 77.02 s
- targets: 1  components: 1  libraries: 10  assets: 89
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 10
- MONITOR: 35
- SAFE: 44

## CERT-In Table 9 completeness: 64.8%

- algorithm: 85.7%
- certificate: 95.0%
- key: 45.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 58.3% of risk with 102.8 eng-weeks; 16 items left over

1. ARK-Genoa [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. ARK-Milan [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. EK/AK CA Root [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. GTS Root R1 [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. GTS Root R2 [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
6. GTS Root R3 [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. GTS Root R4 [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. GlobalSign [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. Google Internet Authority G2 [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
10. Signal Messenger [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
11. Signal Messenger [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
12. aws.nitro-enclaves [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
13. backend1.svr3.test.signal.org [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
14. GlobalSign [signalapp/libsignal] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
15. MD5 [signalapp/libsignal] tier=ACT_NOW -> SHA-256  7.7 wk

## Collectors

- source: 1635
- opengrep: 0
- dependency: 8
- certificate: 601
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
