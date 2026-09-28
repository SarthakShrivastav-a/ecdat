# ECDAT scan: SAML-Toolkits__python3-saml

- id: `67750e8fa10b`  time: 2026-09-18T08:09:39.809021+00:00  duration: 35.19 s
- targets: 1  components: 1  libraries: 1  assets: 22
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 0
- MONITOR: 3
- SAFE: 19

## CERT-In Table 9 completeness: 61.6%

- protocol: 40.0%
- certificate: 100.0%
- algorithm: 100.0%
- key: 53.8%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 100.0% of risk with 11.7 eng-weeks; 0 items left over

1. TLS [SAML-Toolkits/python3-saml] tier=MONITOR -> X25519MLKEM768  2.6 wk
2. private-key:private-key [SAML-Toolkits/python3-saml] tier=MONITOR -> None  4.5 wk
3. private-key:private-key [SAML-Toolkits/python3-saml] tier=MONITOR -> None  4.6 wk

## Collectors

- source: 1
- opengrep: 0
- dependency: 1
- certificate: 59
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
