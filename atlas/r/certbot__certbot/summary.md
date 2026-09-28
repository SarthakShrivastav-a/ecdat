# ECDAT scan: certbot__certbot

- id: `7abc5bb7a2ce`  time: 2026-09-18T08:36:09.939427+00:00  duration: 41.98 s
- targets: 1  components: 1  libraries: 11  assets: 178
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 15
- MONITOR: 43
- SAFE: 120

## CERT-In Table 9 completeness: 72.1%

- algorithm: 85.3%
- protocol: 79.1%
- certificate: 98.8%
- key: 56.7%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 64.3% of risk with 100.4 eng-weeks; 23 items left over

1. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
2. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
3. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
4. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
5. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
6. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
7. TLS [certbot/certbot] tier=ACT_NOW -> X25519MLKEM768  1.9 wk
8. DES [certbot/certbot] tier=ACT_NOW -> AES-256-GCM  2.2 wk
9. 3DES [certbot/certbot] tier=ACT_NOW -> AES-256-GCM  2.4 wk
10. SHA-1 [certbot/certbot] tier=ACT_NOW -> SHA-256  4.1 wk
11. TLS [certbot/certbot] tier=MONITOR -> X25519MLKEM768  1.9 wk
12. TLS [certbot/certbot] tier=MONITOR -> X25519MLKEM768  1.9 wk
13. TLS [certbot/certbot] tier=MONITOR -> X25519MLKEM768  1.9 wk
14. TLS [certbot/certbot] tier=MONITOR -> X25519MLKEM768  1.9 wk
15. nginx.wtf [certbot/certbot] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk

## Collectors

- source: 684
- opengrep: 0
- dependency: 10
- certificate: 528
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
