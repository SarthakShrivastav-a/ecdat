# ECDAT scan: openssh__openssh-portable

- id: `b1bba8d6ae1a`  time: 2026-09-18T08:27:29.663840+00:00  duration: 48.2 s
- targets: 1  components: 1  libraries: 1  assets: 90
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 12
- MONITOR: 15
- SAFE: 63

## CERT-In Table 9 completeness: 57.0%

- algorithm: 91.6%
- key: 45.8%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 65.5% of risk with 103.6 eng-weeks; 8 items left over

1. private-key:RSA [openssh/openssh-portable] tier=ACT_NOW -> None  4.4 wk
2. public-key:RSA [openssh/openssh-portable] tier=ACT_NOW -> None  4.4 wk
3. private-key:unknown [openssh/openssh-portable] tier=MONITOR -> None  3.6 wk
4. ssh-public-key:ECDSA [openssh/openssh-portable] tier=MONITOR -> None  3.6 wk
5. ssh-public-key:ECDSA [openssh/openssh-portable] tier=MONITOR -> None  3.6 wk
6. ssh-public-key:ECDSA [openssh/openssh-portable] tier=MONITOR -> None  3.6 wk
7. ssh-public-key:Ed25519 [openssh/openssh-portable] tier=MONITOR -> None  3.6 wk
8. ssh-public-key:SSH [openssh/openssh-portable] tier=MONITOR -> None  3.6 wk
9. Blowfish [openssh/openssh-portable] tier=ACT_NOW -> AES-256-GCM  9.8 wk
10. X25519 [openssh/openssh-portable] tier=ACT_NOW -> X25519MLKEM768  8.0 wk
11. key:generic-api-key [openssh/openssh-portable] tier=MONITOR -> None  4.4 wk
12. private-key:ECDSA [openssh/openssh-portable] tier=MONITOR -> None  4.4 wk
13. private-key:ECDSA [openssh/openssh-portable] tier=MONITOR -> None  4.4 wk
14. private-key:ECDSA [openssh/openssh-portable] tier=MONITOR -> None  4.4 wk
15. key:generic-api-key [openssh/openssh-portable] tier=MONITOR -> None  4.5 wk

## Collectors

- source: 1037
- opengrep: 0
- dependency: 0
- certificate: 432
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
