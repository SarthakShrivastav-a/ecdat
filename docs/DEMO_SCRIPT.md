# ECDAT demo script (3 minutes, works offline)

Before: `ecdat serve out` is running on http://127.0.0.1:8787 with `out/zoo` and `out/real-world` present.

## 0:00 The question
"Every Indian critical-infrastructure operator has to hand an inventory of its cryptography to auditors by 2027 and be
quantum-safe by 2029. CERT-In already defines the format. Nobody knows what crypto they actually run. ECDAT answers that,
and then answers the harder question: what do we do on Monday morning."

## 0:20 Discovery, live
Run in a terminal: `ecdat scan -c tests/fixtures/zoo/ecdat.yaml -o out/zoo`
Point at the log lines: source, dependency, certificate, binary, container, pcap collectors each reporting. End on the tier
table and "CBOM 1.7 valid: True". One line: "One signed CycloneDX 1.7 file, populated to CERT-In Table 9, 77% complete out
of the box."

## 0:50 Reconciliation
Dashboard > Assets, filter component `pay-image`, open **RSA-2048**. Show evidence from four engines: source (auth.py),
certificate (pay.crt inside the image), binary (libcrypto), theia. "The same key exchange seen in code, in the image, on
the certificate and in the binary: one asset, four pieces of evidence, confidence high because engines agree."

## 1:20 The two axes
Dashboard > Matrix. Point at the right (agile) vs left (rigid) spread. Click the `legacy-hsm-agent` RSA dot: hardcoded C,
no config decoupling, no runtime PQC, defence data for 30 years. Tier ALREADY EXPOSED. "Migration alone does not save this
data; the report says so instead of hiding it."

## 1:50 Drag Z
Move the Z slider from 2041 to 2032 (or click *aggressive*). Tier counts recompute live. "Nobody knows when the quantum
computer arrives, so we do not pretend to. We let you own that assumption and watch what it does to your estate."

## 2:15 The plan
Dashboard > Plan. Set 4 engineers, 6 months. Ordered list, cumulative risk curve, what is left uncovered. Change to 2
engineers, 3 months: the curve flattens and the leftover list grows. "Cost implies effort implies sequencing. This is the
Monday-morning answer."

## 2:40 India overlay + the wire
Overview: DST M1/M2/M3 panel and the CERT-In completeness gauge. Then switch to the `real-world` scan: live probe shows
cloudflare.com and example.com already negotiating X25519MLKEM768, GitHub SSH offering sntrup761x25519, and www.nic.in
still on classical x25519 with an RSA-2048 certificate. "We do not trust the repo. We ask the server."

## 3:00 Close
Export buttons: CBOM 1.7 (signed with ML-DSA-65), VEX, SARIF, PDF. "Inventory for M1. CI gate for M2. Plan for M3."

## Rehearsed pivots (for the finale)
- "Scan this pcap instead": add `{kind: pcap, path: x.pcap, name: capture}` to the YAML, re-run. Under two minutes.
- "Score against CNSA 2.0 / enterprise profile": change `profile:` or read the CNSA overlay column; no code changes.
- "Your binary scanning is weak": agree; show that binary findings are labelled best-effort and medium confidence, and that
  the evaluation table reports per-collector precision.
