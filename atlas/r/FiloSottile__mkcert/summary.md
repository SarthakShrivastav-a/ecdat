# ECDAT scan: FiloSottile__mkcert

- id: `e5e1d0a44ed9`  time: 2026-09-18T09:44:11.580990+00:00  duration: 17.14 s
- targets: 1  components: 1  libraries: 3  assets: 16
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 4
- MONITOR: 4
- SAFE: 8

## CERT-In Table 9 completeness: 71.4%

- algorithm: 71.4%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 31.4 eng-weeks; 0 items left over

1. SHA-1 [FiloSottile/mkcert] tier=ACT_NOW -> SHA-256  8.3 wk
2. ECDSA [FiloSottile/mkcert] tier=ACT_NOW -> ML-DSA-65  7.7 wk
3. RSA [FiloSottile/mkcert] tier=ACT_NOW -> ML-KEM-768  7.7 wk
4. RSA [FiloSottile/mkcert] tier=ACT_NOW -> ML-KEM-768  7.7 wk

## Collectors

- source: 10
- opengrep: 0
- dependency: 2
- certificate: 0
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
