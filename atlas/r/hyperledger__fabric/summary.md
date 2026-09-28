# ECDAT scan: hyperledger__fabric

- id: `588d63445c95`  time: 2026-09-18T09:01:03.861486+00:00  duration: 153.06 s
- targets: 1  components: 1  libraries: 8  assets: 507
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 6
- MONITOR: 27
- SAFE: 474

## CERT-In Table 9 completeness: 61.2%

- algorithm: 80.8%
- protocol: 58.7%
- certificate: 99.0%
- key: 47.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 76.3% of risk with 103.2 eng-weeks; 4 items left over

1. TLS [hyperledger/fabric] tier=ACT_NOW -> X25519MLKEM768  2.6 wk
2. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.2 wk
3. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.2 wk
4. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.2 wk
5. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.2 wk
6. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.5 wk
7. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.5 wk
8. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.5 wk
9. TLS [hyperledger/fabric] tier=MONITOR -> X25519MLKEM768  2.6 wk
10. Org2-child1 [hyperledger/fabric] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.9 wk
11. ca.org1.example.com [hyperledger/fabric] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.1 wk
12. private-key:ECDSA [hyperledger/fabric] tier=MONITOR -> None  3.6 wk
13. Org2 [hyperledger/fabric] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.7 wk
14. MD5 [hyperledger/fabric] tier=ACT_NOW -> SHA-256  10.6 wk
15. key:generic-api-key [hyperledger/fabric] tier=MONITOR -> None  4.4 wk

## Collectors

- source: 422
- opengrep: 0
- dependency: 6
- certificate: 2136
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
