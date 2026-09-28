# ECDAT scan: OpenVPN__openvpn

- id: `343cd511f049`  time: 2026-09-18T08:22:42.747440+00:00  duration: 38.05 s
- targets: 1  components: 1  libraries: 3  assets: 39
- Z (CRQC year): 2041  profile: enterprise  budget: 4 engineers x 6 months

## Tiers

- EXPOSED: 0
- ACT_NOW: 5
- MONITOR: 24
- SAFE: 10

## CERT-In Table 9 completeness: 72.7%

- algorithm: 93.5%
- protocol: 60.0%
- certificate: 88.3%
- key: 57.1%

## Migration plan (4 engineers x 6 months = 103.9 eng-weeks)

- covers 81.4% of risk with 100.3 eng-weeks; 3 items left over

1. TLS [OpenVPN/openvpn] tier=ACT_NOW -> X25519MLKEM768  3.2 wk
2. Test-Client-EC [OpenVPN/openvpn] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
3. Test-Server [OpenVPN/openvpn] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
4. Test-Server-EC [OpenVPN/openvpn] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.2 wk
5. 1.2.840.113549.1.9.1=me@myhost.mydomain,O=OpenVPN-TEST,L=BISHKEK,ST=NA,C=KG [OpenVPN/openvpn] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.4 wk
6. Test-Client [OpenVPN/openvpn] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  2.8 wk
7.  [OpenVPN/openvpn] tier=MONITOR -> ML-DSA-65 certificate (re-issue when the CA supports FIPS 204; hybrid/dual certificates during transition)  3.0 wk
8. private-key:ECDSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
9. private-key:ECDSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
10. private-key:RSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
11. private-key:RSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
12. private-key:RSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
13. private-key:RSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
14. private-key:RSA [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk
15. private-key:unknown [OpenVPN/openvpn] tier=MONITOR -> None  3.6 wk

## Collectors

- source: 270
- opengrep: 0
- dependency: 0
- certificate: 79
- binary: 0

## Honesty notes

- Binary findings are best-effort (constants, symbols, version strings prove presence, not use).
- Z is a user-set estimate anchored to the Global Risk Institute 2025 survey; drag it and re-read the tiers.
- Mosca (X + Y > Z) is applied only to confidentiality primitives; signatures are deadline-driven.
- Patches are suggestions with evidence; nothing is applied automatically.
