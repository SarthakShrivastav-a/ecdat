# ECDAT scan: caddyserver__caddy

- id: `4e8874e235bc`  time: 2026-09-18T08:18:52.417570+00:00  duration: 37.73 s
- targets: 1  components: 1  libraries: 6  assets: 46
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 9
- MONITOR: 15
- SAFE: 22

## CERT-In Table 9 completeness: 71.4%

- protocol: 56.7%
- algorithm: 76.6%
- certificate: 100.0%
- key: 57.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 97.5 eng-weeks; 0 items left over

1. TLS [caddyserver/caddy] tier=ACT_NOW -> X25519MLKEM768  2.3 wk
2. TLS [caddyserver/caddy] tier=ACT_NOW -> X25519MLKEM768  2.3 wk
3. Herong Yang [caddyserver/caddy] tier=ACT_NOW -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.5 wk
4. public-key:RSA [caddyserver/caddy] tier=ACT_NOW -> None  4.4 wk
5. TLS [caddyserver/caddy] tier=MONITOR -> X25519MLKEM768  1.9 wk
6. *.caddy.localhost [caddyserver/caddy] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
7. Easy-RSA CA [caddyserver/caddy] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
8. a.caddy.localhost [caddyserver/caddy] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
9. TLS [caddyserver/caddy] tier=MONITOR -> X25519MLKEM768  2.3 wk
10. RSA [caddyserver/caddy] tier=ACT_NOW -> ML-KEM-768  7.5 wk
11. MD5 [caddyserver/caddy] tier=ACT_NOW -> SHA-256  8.8 wk
12. private-key:RSA [caddyserver/caddy] tier=MONITOR -> None  3.6 wk
13. private-key:RSA [caddyserver/caddy] tier=MONITOR -> None  3.6 wk
14. X25519 [caddyserver/caddy] tier=ACT_NOW -> X25519MLKEM768  7.2 wk
15. ECDH [caddyserver/caddy] tier=ACT_NOW -> X25519MLKEM768  7.6 wk

## Collectors

- source: 70
- opengrep: 0
- dependency: 3
- certificate: 53
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
