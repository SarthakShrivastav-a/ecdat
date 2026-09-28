# ECDAT scan: DNSCrypt__dnscrypt-proxy

- id: `667ed9be27e3`  time: 2026-09-18T08:25:21.604764+00:00  duration: 55.71 s
- targets: 1  components: 1  libraries: 6  assets: 37
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 5
- MONITOR: 12
- SAFE: 20

## CERT-In Table 9 completeness: 74.4%

- algorithm: 81.9%
- protocol: 60.0%
- certificate: 100.0%
- key: 49.0%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 92.1 eng-weeks; 0 items left over

1. localhost [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
2. TLS [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> X25519MLKEM768  2.2 wk
3. TLS [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> X25519MLKEM768  2.5 wk
4. TLS [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> X25519MLKEM768  2.6 wk
5. X25519 [DNSCrypt/dnscrypt-proxy] tier=ACT_NOW -> X25519MLKEM768  7.2 wk
6. private-key:RSA [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> None  3.6 wk
7. Ed25519 [DNSCrypt/dnscrypt-proxy] tier=ACT_NOW -> ML-DSA-65  8.0 wk
8. key:generic-api-key [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> None  4.4 wk
9. public-key:RSA [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> None  4.4 wk
10. key:generic-api-key [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> None  4.5 wk
11. SHA-1 [DNSCrypt/dnscrypt-proxy] tier=ACT_NOW -> SHA-256  11.3 wk
12. ECDSA [DNSCrypt/dnscrypt-proxy] tier=ACT_NOW -> ML-DSA-65  9.4 wk
13. key:generic-api-key [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> None  4.8 wk
14. RSA [DNSCrypt/dnscrypt-proxy] tier=ACT_NOW -> ML-KEM-768  14.7 wk
15. AES [DNSCrypt/dnscrypt-proxy] tier=MONITOR -> AES-256  10.3 wk

## Collectors

- source: 229
- opengrep: 0
- dependency: 3
- certificate: 30
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
