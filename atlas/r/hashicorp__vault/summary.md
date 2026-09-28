# ECDAT scan: hashicorp__vault

- id: `0892ff2f1adb`  time: 2026-09-18T09:13:40.115147+00:00  duration: 198.77 s
- targets: 1  components: 1  libraries: 8  assets: 205
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 73
- ACT_NOW: 23
- MONITOR: 31
- SAFE: 78

## CERT-In Table 9 completeness: 61.7%

- algorithm: 85.2%
- protocol: 60.0%
- certificate: 87.7%
- key: 51.6%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 34.9% of risk with 102.1 eng-weeks; 88 items left over

1. Vishal Nayak [hashicorp/vault] tier=EXPOSED -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. expired.vault.com [hashicorp/vault] tier=EXPOSED -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. github.hashicorp.com [hashicorp/vault] tier=EXPOSED -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. minikubeCA [hashicorp/vault] tier=EXPOSED -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
6. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
7. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
8. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
9. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
10. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
11. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
12. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
13. TLS [hashicorp/vault] tier=EXPOSED -> X25519MLKEM768  2.2 wk
14. TLS [hashicorp/vault] tier=ACT_NOW -> X25519MLKEM768  2.3 wk
15. cert.example.com [hashicorp/vault] tier=EXPOSED -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.8 wk

## Collectors

- source: 587
- opengrep: 0
- dependency: 5
- certificate: 739
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
