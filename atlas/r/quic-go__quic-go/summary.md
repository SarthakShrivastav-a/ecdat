# ECDAT scan: quic-go__quic-go

- id: `27043815d681`  time: 2026-09-18T08:22:01.400515+00:00  duration: 35.78 s
- targets: 1  components: 1  libraries: 3  assets: 39
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 2
- MONITOR: 6
- SAFE: 31

## CERT-In Table 9 completeness: 69.4%

- algorithm: 77.8%
- protocol: 60.0%
- certificate: 76.7%
- key: 55.5%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 38.5 eng-weeks; 0 items left over

1. TLS [quic-go/quic-go] tier=MONITOR -> X25519MLKEM768  2.2 wk
2. MD5 [quic-go/quic-go] tier=ACT_NOW -> SHA-256  6.7 wk
3. key:generic-api-key [quic-go/quic-go] tier=MONITOR -> None  4.5 wk
4. key:generic-api-key [quic-go/quic-go] tier=MONITOR -> None  4.5 wk
5. Ed25519 [quic-go/quic-go] tier=ACT_NOW -> ML-DSA-65  11.0 wk
6. AES [quic-go/quic-go] tier=MONITOR -> AES-256  9.6 wk

## Collectors

- source: 59
- opengrep: 0
- dependency: 2
- certificate: 48
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
