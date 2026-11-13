# ECDAT: The Complete Run Guide

This guide covers everything you need to install, run, demo and understand ECDAT, from a fresh computer to a live dashboard.
Every command here was run on a fresh clone of the repository (Windows 11, Python 3.11, Node 20) on 11 Nov 2026,
and the numbers shown are from that run.

> **Short on time?** Do [Part 3 (Install)](#part-3-install-ecdat) and then [Part 4 (Your first scan in 5 minutes)](#part-4-your-first-scan-in-5-minutes).
> That is all you need for a demo.

---

## Contents

1. [What ECDAT is, in plain words](#part-1-what-ecdat-is-in-plain-words)
2. [What you need before you start](#part-2-what-you-need-before-you-start)
3. [Install ECDAT](#part-3-install-ecdat)
4. [Your first scan in 5 minutes](#part-4-your-first-scan-in-5-minutes)
5. [Reading the scan output](#part-5-reading-the-scan-output)
6. [The files ECDAT produces](#part-6-the-files-ecdat-produces)
7. [The dashboard](#part-7-the-dashboard)
8. [Scanning your own project, server or files](#part-8-scanning-your-own-project-server-or-files)
9. [The config file, every option explained](#part-9-the-config-file-every-option-explained)
10. [Every command, with examples](#part-10-every-command-with-examples)
11. [Signatures: proving a CBOM was not changed](#part-11-signatures-proving-a-cbom-was-not-changed)
12. [The CI gate: blocking new weak crypto](#part-12-the-ci-gate-blocking-new-weak-crypto)
13. [The REST API](#part-13-the-rest-api)
14. [Optional extra engines](#part-14-optional-extra-engines)
15. [Running the tests](#part-15-running-the-tests)
16. [Running with no internet (air-gapped)](#part-16-running-with-no-internet-air-gapped)
17. [A 3-minute demo script for the presentation](#part-17-a-3-minute-demo-script-for-the-presentation)
18. [Advanced scripts (Atlas, India survey, website)](#part-18-advanced-scripts-atlas-india-survey-website)
19. [Troubleshooting](#part-19-troubleshooting)
20. [Where things live in the code](#part-20-where-things-live-in-the-code)
21. [Glossary](#part-21-glossary)

---

## Part 1: What ECDAT is, in plain words

Almost everything secure on the internet (UPI, Aadhaar logins, banking, HTTPS) is protected by two pieces of maths:
**RSA** and **elliptic-curve cryptography (ECC)**. A large enough **quantum computer** will be able to break both.
Attackers can already copy encrypted data today and decrypt it later, once that computer exists. This is called
**"harvest now, decrypt later"**.

India's DST/National Quantum Mission roadmap says critical systems must be quantum-safe by **2029**. The first step
is to know *where* your cryptography is. Most organisations don't know.

**ECDAT does three things:**

1. **Finds** every piece of cryptography in an organisation: source code, libraries, certificates, compiled
   programs, container images, live servers and recorded network traffic.
2. **Judges** which of it a quantum computer will break, and how urgent each one is, using **Mosca's rule**
   (`X + Y > Z`, explained in [Part 5](#part-5-reading-the-scan-output)).
3. **Plans** the fix: which items to change first, and to what, within the number of engineers and months you have.

Everything ends up in one file called a **CBOM** (Cryptographic Bill of Materials), in the international
**CycloneDX 1.7** format, digitally **signed** with the post-quantum algorithm **ML-DSA-65**.
ECDAT runs **fully offline**: it only uses the network when you ask it to probe a live server.

---

## Part 2: What you need before you start

### Required

| What | Version | How to check | Where to get it |
|---|---|---|---|
| **Python** | **3.11 or newer** (3.11 and 3.13 tested) | `python --version` | https://www.python.org/downloads/ (tick "Add Python to PATH") |
| **Git** | any | `git --version` | https://git-scm.com/downloads |
| Internet (once) | | | to download the code and Python packages |

> Python 3.10 or older **will not work**: the project requires 3.11+.
> If you have several Pythons on Windows, `py -0` lists them and `py -3.11` picks 3.11.

### Optional (everything works without these)

| What | What it adds | Check |
|---|---|---|
| **Node.js 20.19+** (or 22.12+) and npm | Building the interactive **dashboard** ([Part 7](#part-7-the-dashboard)) | `node --version` |
| **OpenSSL** | Lets `zoo build` make an old SHA-1 test certificate (Git for Windows already ships one) | `openssl version` |
| **Java JDK (keytool)** | Lets `zoo build` make Java keystore test files | `keytool -help` |
| **Go** | Lets `zoo build` compile a test Go program; also used to install `cbomkit-theia` and `crane` | `go version` |
| OpenGrep, Syft, cbomkit-theia, crane, Wireshark (tshark) | Extra "second opinion" engines ([Part 14](#part-14-optional-extra-engines)) | `ecdat tools` |

If an optional tool is missing, ECDAT skips that part and tells you. Nothing breaks.

---

## Part 3: Install ECDAT

### Step 1: Get the code

```powershell
git clone https://github.com/SarthakShrivastav-a/ecdat.git
cd ecdat
```

### Step 2: Create a virtual environment

A virtual environment (`.venv`) is a private folder of Python packages just for this project, so nothing
clashes with other projects.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
```

**macOS / Linux:**

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
```

### Step 3: Install ECDAT and its packages

Run these three commands (about **3 minutes** on a normal connection).

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\python -m pip install -e . --no-deps
.\.venv\Scripts\python -m pip install cryptography cyclonedx-python-lib lief scapy "tree-sitter>=0.25" tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-go tree-sitter-c yara-python fastapi "uvicorn[standard]" pyyaml typer rich jsonschema reportlab dilithium-py kyber-py httpx python-multipart cryptolyzer pycryptodomex pyasn1 pyasn1-modules javaobj-py3 pytest
.\.venv\Scripts\python -m pip install --no-deps pyjks
```

**macOS / Linux:** the same three commands, with `.venv/bin/python` instead of `.\.venv\Scripts\python`.

What these do:

- The first line installs ECDAT itself in "editable" mode (`-e`), so code changes take effect immediately.
- The second line installs everything ECDAT uses, plus `pytest` for running the tests.
- The third line installs `pyjks` (Java keystore reader) **without** its extra dependency, which needs a C compiler
  and isn't used.

### Step 4: Turn the environment on (activate it)

After activating, you can type `ecdat` directly instead of the long path.

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
```

> If PowerShell says *"running scripts is disabled on this system"*, run this once and try again:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
> Or skip activation entirely and always type `.\.venv\Scripts\ecdat` instead of `ecdat`.

**Windows (Command Prompt):** `.venv\Scripts\activate.bat`

**macOS / Linux:** `source .venv/bin/activate`

You'll see `(.venv)` at the start of your prompt. **Activate again every time you open a new terminal.**

### Step 5: Check it works

```powershell
ecdat --help
ecdat tools
```

`ecdat --help` lists all commands. `ecdat tools` shows which optional engines were found, for example:

```
 ecdat                0.1.0
 opengrep             not found (pure-Python fallback in use)
 syft                 not found (pure-Python fallback in use)
 cbomkit-theia        - CycloneDXv1.6
 crane                v0.22.1
 tshark               not found (pure-Python fallback in use)
 cryptography         50.0.2
 ...
```

"not found" is fine: that engine is optional.

---

## Part 4: Your first scan in 5 minutes

ECDAT ships with a test estate called the **"crypto zoo"** (`tests/fixtures/zoo/`): code in five languages, an
nginx config, certificates, keystores, compiled binaries, a container image and network captures, all with known
cryptography planted in them. It is the best way to see everything working.

Run all of these **from the `ecdat` folder** with the environment activated.

### Step 1: Build the zoo's test files (about 50 seconds)

Some test files (certificates, keystores, binaries, the container image, network captures) are generated rather
than stored in Git. Make them with:

```powershell
ecdat zoo build
```

> Run it from the `ecdat` folder (a source checkout): it uses the repo's `scripts/build_zoo.py`.
> `python -m ecdat.cli zoo build` does exactly the same thing if you prefer it.

You'll see some yellow `WARNING: ... winpcap is not installed` lines from the network library. **Ignore them**:
they're harmless. At the end it lists what it made:

```
"certs":  bundle.pem, ca_rsa4096.crt, ecdsa_p256.crt, keystore.jks, modern.jks, pay.p12, ...
"bin":    libzoocrypto.so, zoobin
"images": zoo-docker.tar, zoo-oci.tar
"pcaps":  smtp_starttls.pcap, tls_handshake.pcap
```

(If OpenSSL, Java or Go are missing, it skips the few files that need them and the scan still works.)

### Step 2: Scan the zoo (about 10 seconds)

```powershell
ecdat scan -c tests/fixtures/zoo/ecdat.yaml -o out/zoo
```

- `-c` is the **config file**: what to scan.
- `-o` is the **output folder**: where results go.

You'll see the five phases run live, ending with something like:

```
4 DECIDE  tiers at this Z, then a plan that fits the budget
already exposed        2                                      1%
act now               39  ######                              20%
monitor               84  #############                       43%
safe                  72  ###########                         37%

scan complete
  assets 197 across 11 components   evidence 636 findings
  CycloneDX 1.7 valid yes   CERT-In Table 9 76.8%   signed ML-DSA-65
  plan removes 36.9% of quantum risk in 102.1 engineer-weeks at Z=2041
```

(Your counts may differ slightly depending on which optional tools you have.)

### Step 3: Open the report

Open `out\zoo\report.html` in a browser (double-click it), or `out\zoo\report.pdf`.

```powershell
start out\zoo\report.html          # Windows
open out/zoo/report.html           # macOS
xdg-open out/zoo/report.html       # Linux
```

### Step 4: Check the scan was accurate

```powershell
ecdat evaluate out/zoo/result.json
```

This compares what ECDAT found against the answer key (`tests/fixtures/zoo/truth.yaml`):

```
evaluation: precision 1.0   recall 1.0  F1 1.0  (PASS vs gates 0.85/0.95)
tp 60   fp 0   fn 0   expected 60
```

- **Precision 1.0**: everything it reported was real (no false alarms).
- **Recall 1.0**: it found all 60 planted items (nothing missed).

### Step 5 (optional): See the dashboard

See [Part 7](#part-7-the-dashboard). In short:

```powershell
cd web; npm ci; npm run build; cd ..
ecdat serve out
```

Then open **http://127.0.0.1:8787**.

That's the whole tool working end to end.

---

## Part 5: Reading the scan output

A scan runs in **five phases**:

| # | Phase | What happens, simply |
|---|---|---|
| 1 | **DISCOVER** | Every "collector" (scanner) that fits each target runs. Each finding records the exact file and line. |
| 2 | **RECONCILE** | The same thing found in several places (say, RSA in the code, in a certificate and in a binary) is merged into **one asset with many proofs**. 636 findings became 197 assets. |
| 3 | **ANALYSE** | Each asset is classified: quantum-broken, weakened or safe? How long must the data stay secret? How hard is it to change? |
| 4 | **DECIDE** | Each asset gets a **tier**, and the planner picks what to fix first within your budget. |
| 5 | **OUTPUTS** | Nine files are written, and the CBOM is signed. |

### The four tiers (verdicts)

| Tier | Meaning in plain words | Example |
|---|---|---|
| **EXPOSED** ("already exposed") | Too late to fully protect: data stolen today will still be secret-worthy when the quantum computer arrives, even if you start fixing now. | RSA protecting defence data that must stay secret for 30 years |
| **ACT_NOW** | Must start migrating now to finish in time, or it's already broken by normal computers (MD5, SHA-1, DES). | RSA on a payments API |
| **MONITOR** | Vulnerable, but there's still time. Plan it. | An RSA certificate that is renewed every year |
| **SAFE** | Quantum-safe, or not used for security at all. | AES-256, SHA-384, ML-KEM, or MD5 used only as a cache key |

### Mosca's rule: `X + Y > Z`

- **X** = how many years the data must stay secret (set by its `data_class`: defence 30, health 25, identity 20,
  financial 10, PII 7, logs 1, sessions ~0.1, generic 5).
- **Y** = how many years it will take to migrate this piece (worked out from how "agile" the code is).
- **Z** = how many years until a quantum computer can break RSA/ECC. **You** choose this year (default **2041**).

If **X + Y is bigger than Z**, the data is at risk. This rule is only applied to **encryption/key exchange**:
signatures can't be "harvested and decrypted later", so they're judged by deadlines instead.

### Other numbers you'll see

- **CERT-In Table 9 completeness**: how many of the fields that India's CERT-In CBOM guideline asks for are filled in.
- **Agility (0–100)**: how easy it is to swap the algorithm. Hard-coded in C is low; read from a config file is high.
- **Plan removes X% of risk in Y engineer-weeks**: what your budget achieves, in priority order.

---

## Part 6: The files ECDAT produces

Every scan writes these into the output folder (for example `out/zoo/`):

| File | What it is | Open it with |
|---|---|---|
| `result.json` | **Everything**: every asset, its evidence, risk and the plan. Other commands read this. | Any text editor |
| `cbom.json` | The **CBOM** in CycloneDX 1.7 format (checked against the official schema) | Text editor / CycloneDX tools |
| `cbom.json.mldsa65.sig` | The **ML-DSA-65 signature** of `cbom.json` | `ecdat verify` |
| `ecdat-mldsa65.pub` | The **public key** anyone can use to check the signature | `ecdat verify --pubkey` |
| `vex.json` | **VEX** statements: which findings matter and which are not exploitable here | Text editor |
| `findings.sarif` | **SARIF** findings, the format GitHub code scanning and IDEs understand | GitHub / VS Code SARIF viewer |
| `assets.csv` | One row per asset | Excel / Google Sheets |
| `report.html` | A readable report | Browser |
| `report.pdf` | The same report as a PDF | PDF reader |
| `summary.md` | A short Markdown summary | Any Markdown viewer |

**Signing keys** are created on the first scan in a `keys/` folder **next to** the output folder (for `-o out/zoo`
that's `out/keys/`):

- `out/keys/ecdat-mldsa65.key` is the **private key**. Keep it secret and never share or commit it (`keys/` is
  already in `.gitignore`).
- `out/keys/ecdat-mldsa65.pub` is the **public key**. It's safe to share.

The same key is reused for every later scan in that folder, so all your CBOMs carry the same signer.

---

## Part 7: The dashboard

The dashboard is a web app (React) that shows your scans visually. The Python server (`ecdat serve`) provides the
data and also hosts the built dashboard.

### Build it (once, or after changing anything in `web/`)

Needs Node.js 20.19+ ([Part 2](#part-2-what-you-need-before-you-start)).

```powershell
cd web
npm ci            # installs exactly the versions in package-lock.json (~5 s)
npm run build     # creates web/dist/ (~1 s)
cd ..
```

A yellow warning *"Some chunks are larger than 500 kB"* is normal. Ignore it.

### Start it

```powershell
ecdat serve out
```

Open **http://127.0.0.1:8787** in your browser. Press **Ctrl + C** in the terminal to stop it.

- `ecdat serve out` shows **every scan** inside `out/` (each sub-folder that has a `result.json` is one scan).
- Change the port: `ecdat serve out --port 9000`
- Let other devices on your Wi-Fi open it: `ecdat serve out --host 0.0.0.0` (then use your PC's IP address)
- If you **didn't** build the dashboard, the same address shows a simple page with links to each HTML report instead.

### What you can do on it

| View | Link | What it shows |
|---|---|---|
| **Overview** | `#overview` | The verdict (how many assets can't wait), the tier ribbon, CERT-In completeness, India's DST milestones. **Drag the quantum-year (Z) slider** and every tier recalculates live. |
| **Matrix** | `#matrix` | Each asset as a dot: risk (up/down) against how hard it is to fix (left/right). Hover any dot. |
| **Assets** | `#assets` | The full findings table. Filter (for example by RSA) and click a row to see the exact `file:line`, the evidence from each engine, the agility breakdown and the recommended replacement. |
| **Plan** | `#plan` | Set **engineers** and **months**; see the ordered fix list and the "risk removed" curve against engineer-weeks. |

Export buttons on the dashboard download the CBOM (signed), VEX, SARIF, CSV, HTML and PDF.

### Developer mode (live reload while editing the UI)

Open two terminals:

```powershell
# terminal 1: the data server (must be on the default port 8787)
ecdat serve out

# terminal 2: the UI with hot reload
cd web
npm run dev
```

Open **http://localhost:5181**. The UI automatically forwards `/api` calls to port 8787.

### The online version

A static copy runs on GitHub Pages, so no install is needed to show it:

- Evidence hub: https://sarthakshrivastav-a.github.io/ecdat/
- Dashboard: https://sarthakshrivastav-a.github.io/ecdat/dashboard
- CBOM Atlas (109 signed CBOMs): https://sarthakshrivastav-a.github.io/ecdat/atlas
- India readiness snapshot: https://sarthakshrivastav-a.github.io/ecdat/snapshot

---

## Part 8: Scanning your own project, server or files

Everything is driven by a small **YAML config file**. Make a new file anywhere, for example `my-scan.yaml`.

> **Paths in the config are relative to the config file's own folder**, not to where you run the command.
> Absolute paths (`C:\code\myapp`) always work.

### Example A: scan a code folder

```yaml
name: my-app
params: {z_year: 2041, engineers: 2, months: 3, profile: enterprise}
targets:
  - {kind: dir, path: C:/code/my-app, name: my-app, zone: external, data_class: pii, criticality: high}
```

```powershell
ecdat scan -c my-scan.yaml -o out/my-app
```

This runs the source, dependency, certificate and binary collectors (plus OpenGrep if you have it) over that folder.

### Example B: check a live website and an SSH server

```yaml
name: live-check
params: {z_year: 2041, engineers: 2, months: 3, profile: enterprise}
targets:
  - {kind: endpoints, name: public-sites, zone: external,
     endpoints: ["example.com:443 tls", "github.com:22 ssh"]}
```

Tested result (about 20 seconds):

```
tls://example.com:443  TLS 1.3, key exchange X25519MLKEM768, post-quantum: YES  -> SAFE
                       certificate ECDSA P-256 (issued by Cloudflare)
ssh://github.com:22    offers mlkem768x25519-sha256 and sntrup761x25519 first, post-quantum: YES -> SAFE
```

ECDAT really connects to the server and reads which key exchange it picks. It offers the hybrid post-quantum
group **X25519MLKEM768** in its own handshake. Endpoint format: `host:port type`, where type is `tls`, `ssh`, `smtp`,
`imap` or `pop3` (the last three upgrade with STARTTLS).

> Only probe servers you're allowed to test. ECDAT does a normal handshake (what a browser does): no attacks, no
> logins, no crawling.

### Example C: certificates and keystores

```yaml
targets:
  - {kind: certs, path: pki/, name: pki, zone: external, passwords: [changeit, mypassword]}
```

Reads PEM, DER, PKCS#12 (`.p12`/`.pfx`), Java keystores (`.jks`) and OpenSSH keys. `passwords` are tried to open
protected keystores. If you leave `passwords` out, ECDAT tries `"", changeit, password, zoo, zoopass, secret`. If you
set it, **only your list** is tried, so include `changeit` yourself if you still want it.

### Example D: a container image (no Docker needed)

```powershell
docker save myimage:latest -o images/myimage.tar      # on any machine that has Docker
```

```yaml
targets:
  - {kind: image, path: images/myimage.tar, name: my-image, zone: external, data_class: financial}
```

ECDAT unpacks the image layers itself and runs the file collectors on the result. It also accepts OCI layout folders.

### Example E: a network capture (.pcap)

Record traffic with Wireshark, save it as `.pcap`, then:

```yaml
targets:
  - {kind: pcap, path: captures/traffic.pcap, name: office-capture, zone: internal}
```

It rebuilds the TLS handshakes (including STARTTLS email) and records what was **actually negotiated**.

### Example F: a single compiled program

```yaml
targets:
  - {kind: binary, path: bin/myservice.exe, name: my-service}
```

Binary results are **best-effort** (capped at "medium" confidence): they prove an algorithm is *present*, not
necessarily *used*.

### Example G: everything at once

```yaml
name: payments-estate
params: {z_year: 2041, engineers: 4, months: 6, profile: cii}
targets:
  - {kind: dir,       path: services/payments, name: payments-api, zone: external, data_class: financial, criticality: high}
  - {kind: certs,     path: pki/,              name: pki,          zone: external, passwords: [changeit]}
  - {kind: image,     path: images/pay.tar,    name: pay-image,    zone: external}
  - {kind: endpoints, name: edge, zone: external, endpoints: ["pay.example.in:443 tls", "bastion.example.in:22 ssh"]}
  - {kind: pcap,      path: captures/mail.pcap, name: mail}
```

A good ready-made example to copy is `tests/fixtures/zoo/ecdat.yaml` (11 targets, 6 kinds).

---

## Part 9: The config file, every option explained

```yaml
name: my-scan                 # any label; shown in reports and the dashboard
params:                       # all optional; defaults shown
  z_year: 2041                # the year you assume a quantum computer can break RSA/ECC (Z)
  engineers: 4                # people available for migration (planner budget)
  months: 6                   # months available (planner budget)
  profile: cii                # cii = critical infrastructure deadlines (2027/2028/2029)
                              # enterprise = other organisations (2028/2030/2033)
  now_year: 2026              # "today", used to work out years until Z
  y_default: 3.0              # migration years used when it can't be estimated
  use_external_tools: true    # false = never call OpenGrep/Syft/theia/tshark/CryptoLyzer
  passwords: ["", changeit, password, zoo, zoopass]   # keystore passwords to try
collectors: [source, certificate]   # optional: run ONLY these collectors (default: all that apply)
targets:
  - kind: dir                 # required, see table below
    path: services/payments   # file or folder (relative to this YAML file)
    name: payments-api        # label for this component
    zone: external            # external (internet-facing) | internal (default)
    data_class: financial     # sets X (years secret), see table below; guessed from names if omitted
    criticality: high         # low 0.8x | medium 1.0x | high 1.25x | critical 1.5x priority
    passwords: [changeit]     # certs targets: keystore passwords to try (replaces the default list)
    endpoints: ["host:443 tls"]   # endpoints targets only
```

### Target kinds and what runs on them

| `kind` | Give it | Collectors that run |
|---|---|---|
| `dir` | a folder | source, opengrep, dependency, certificate, binary |
| `repo` | a folder that is a checked-out repository (same as `dir`) | same as `dir` |
| `certs` | a folder or file of certificates/keystores | certificate |
| `image` | a `docker save` / OCI tar, or an OCI layout folder | container (+ all file collectors inside it) |
| `endpoints` | a list `endpoints: ["host:port type", ...]` | protocol (live network) |
| `pcap` | a `.pcap` / `.pcapng` file | pcap |
| `binary` | one compiled file or folder of them | binary |

Collector names for the `collectors:` list: `source`, `opengrep`, `dependency`, `certificate`, `binary`,
`container`, `protocol`, `pcap`.

### Data classes (X = years the data must stay secret)

| `data_class` | Years | Auto-detected from words like |
|---|---|---|
| `defence` | 30 | defence, military, classified, hsm, strategic |
| `health` | 25 | patient, ehr, medical, hospital, abha |
| `identity` | 20 | aadhaar, passport, kyc, biometric, digilocker |
| `financial` | 10 | payment, bank, upi, ledger, card, wallet |
| `pii` | 7 | user, customer, email, phone, profile, student |
| `logs` | 1 | log, audit, metrics, telemetry |
| `session` | 0.1 | session, token, jwt, cookie, otp |
| `generic` | 5 | (fallback) |

These live in `ecdat/knowledge/data_classes.yaml` and can be edited.

### Command-line overrides

Any `params` value can be overridden without editing the file:

```powershell
ecdat scan -c my-scan.yaml -o out/x --z-year 2032 --engineers 8 --months 12 --profile enterprise
```

---

## Part 10: Every command, with examples

Run `ecdat <command> --help` for the built-in help on any command.

### `ecdat scan`: run a full scan

```powershell
ecdat scan -c CONFIG.yaml -o OUTPUT_FOLDER [options]
```

| Option | Meaning |
|---|---|
| `-c, --config` | the YAML config (**required**) |
| `-o, --out` | output folder (default `out`) |
| `--z-year 2032` | override Z |
| `--engineers 8` / `--months 12` | override the budget |
| `--profile cii\|enterprise` | override the deadline profile |
| `--no-external-tools` | use only the built-in Python engines (faster, more predictable) |
| `--no-sign` | don't sign the CBOM |

Exit code 2 means the CBOM failed schema validation. To record the whole terminal session as an SVG picture,
set `ECDAT_RECORD_SVG=scan.svg` first (PowerShell: `$env:ECDAT_RECORD_SVG="scan.svg"`).

### `ecdat recompute`: "what if?" without rescanning

Re-scores a saved result with a different quantum year, budget or profile. It's instant, because nothing is rescanned.

```powershell
ecdat recompute out/zoo/result.json --z-year 2032 --engineers 2 --months 3
```

Tested result: with an aggressive Z = 2032 and a small team, EXPOSED jumps from 2 to **22**, and the plan covers
only 16.3% of the risk. Add `-o out/zoo-2032` to save a full new set of outputs.
Handy presets: **2032** (aggressive), **2035** (NIST disallows RSA/ECC), **2041** (expert median, the default).

### `ecdat report`: produce one output format

```powershell
ecdat report out/zoo/result.json                                  # Markdown summary to the screen
ecdat report out/zoo/result.json --format html -o report.html
ecdat report out/zoo/result.json --format pdf  -o report.pdf
ecdat report out/zoo/result.json --format csv  -o assets.csv
ecdat report out/zoo/result.json --format sarif -o findings.sarif
ecdat report out/zoo/result.json --format cbom -o cbom.json       # unsigned
ecdat report out/zoo/result.json --format vex  -o vex.json
```

### `ecdat evaluate`: accuracy against the answer key

```powershell
ecdat evaluate out/zoo/result.json                 # uses tests/fixtures/zoo/truth.yaml
ecdat evaluate out/zoo/result.json --strict        # exit code 1 if precision < 0.85 or recall < 0.95
ecdat evaluate out/zoo/result.json -o eval.json    # save the numbers
```

Only meaningful for zoo scans (it needs a truth file; use `--truth` for another one).

### `ecdat verify`: check a CBOM's signature

```powershell
ecdat verify out/zoo/cbom.json
ecdat verify out/zoo/cbom.json --pubkey out/keys/ecdat-mldsa65.pub
```

See [Part 11](#part-11-signatures-proving-a-cbom-was-not-changed).

### `ecdat gate`: CI check

```powershell
ecdat gate -c CONFIG.yaml --baseline cbom-baseline.json --policy no-new-vulnerable
```

See [Part 12](#part-12-the-ci-gate-blocking-new-weak-crypto).

### `ecdat serve`: API + dashboard

```powershell
ecdat serve out [--host 127.0.0.1] [--port 8787]
```

See [Part 7](#part-7-the-dashboard) and [Part 13](#part-13-the-rest-api).

### `ecdat tools`: which optional engines are installed

```powershell
ecdat tools
```

### `zoo build`: generate the test estate

```powershell
ecdat zoo build                 # writes into tests/fixtures/zoo
ecdat zoo build --out D:/zoo    # somewhere else
```

---

## Part 11: Signatures: proving a CBOM was not changed

Each CBOM is signed with **ML-DSA-65** (NIST FIPS 204), a **post-quantum** signature, so even a future quantum
computer can't forge it.

```powershell
# integrity only: was the file changed after signing?
ecdat verify out/zoo/cbom.json
# OK  cbom.json  ML-DSA-65 (FIPS 204) sha256 9b69d7669ac7233e...  embedded key (integrity only; ...)

# integrity + identity: was it signed by the key I trust?
ecdat verify out/zoo/cbom.json --pubkey out/keys/ecdat-mldsa65.pub
# OK  cbom.json  ML-DSA-65 (FIPS 204) sha256 9b69d7669ac7233e...  trusted key
```

**Tamper test (good for a demo):** change even one character in `cbom.json` and verify again:

```
FAIL  tamper.json  ML-DSA-65 (FIPS 204) ...
```

Exit code is 0 for OK and 1 for FAIL. Exit code 2 means there's no `.sig` file next to the CBOM.

**Check a published CBOM from the Atlas:**

```powershell
curl -O https://sarthakshrivastav-a.github.io/ecdat/ecdat-mldsa65.pub
ecdat verify cbom.json --pubkey ecdat-mldsa65.pub
```

---

## Part 12: The CI gate: blocking new weak crypto

`ecdat gate` scans the code **now**, compares it with a saved **baseline** CBOM, and **fails** (exit code 1) if
the policy is broken. Put it in a CI pipeline to stop anyone adding new quantum-vulnerable crypto.

### The three policies

| `--policy` | Fails when |
|---|---|
| `no-new-vulnerable` (default) | something vulnerable appears that wasn't in the baseline (old problems are tolerated for now) |
| `no-vulnerable` | **anything** vulnerable exists at all |
| `dst-m2` | India DST milestone M2 ("no new classical-only deployments"): a new Shor-broken asset on an external component, or any new classical-only key exchange |

### Try it locally

```powershell
copy out\zoo\cbom.json out\cbom-baseline.json        # today's state = the baseline
ecdat gate -c tests/fixtures/zoo/ecdat.yaml --baseline out/cbom-baseline.json --policy no-new-vulnerable --no-external-tools -o out/gate
#  ## ECDAT CI gate: PASS  (policy: no-new-vulnerable)   -> exit 0
ecdat gate -c tests/fixtures/zoo/ecdat.yaml --baseline out/cbom-baseline.json --policy no-vulnerable --no-external-tools -o out/gate2
#  ## ECDAT CI gate: FAIL  (policy: no-vulnerable)        -> exit 1
```

The gate writes `gate.md` (a summary listing each blocking finding and its recommended replacement), plus the
current CBOM, VEX and SARIF, into the `-o` folder.

### Use it in GitHub Actions (in *another* project)

The template is `.github/workflows/ecdat-gate.yml`. To adopt it in a project you want to protect:

1. Copy `ecdat-gate.yml` into that project's `.github/workflows/`.
2. Add an `ecdat.yaml` to that project's root (for example one `dir` target with `path: .`).
3. Make the baseline once: `ecdat scan -c ecdat.yaml -o out/base --no-sign`, then commit `out/base/cbom.json`
   as `cbom-baseline.json`.
   (If you skip this, the workflow uses each run's own scan as the baseline and the gate always passes, with a
   warning, until you commit one.)
4. Copy ECDAT's `requirements-ci.txt` (repo root) into that project. The workflow installs from it, then installs
   `pyjks` separately with `--no-deps`.
5. Make sure the job can install ECDAT itself: the template runs `pip install . --no-deps`, which only works inside
   the ECDAT repo. In another project, change that line to
   `pip install --no-deps git+https://github.com/SarthakShrivastav-a/ecdat.git` (the header comment in the
   workflow says the same).

On every pull request it then scans, uploads the CBOM/VEX/SARIF as artefacts, shows the findings in GitHub
**code scanning**, and posts `gate.md` as a PR comment.

> This workflow is a **template**. In the ECDAT repo itself there's no root `ecdat.yaml`, so the scan step
> fails there; `ecdat.yaml` and `cbom-baseline.json` belong to the project that adopts it.

---

## Part 13: The REST API

`ecdat serve out` also gives you a REST API. Interactive API docs are at **http://127.0.0.1:8787/docs**.

| Method | Path | What it does |
|---|---|---|
| GET | `/api/health` | `{"ok": true, "version": "0.1.0"}` |
| GET | `/api/tools` | installed engines and versions |
| GET | `/api/results` | list of scans (id, name, assets, tiers, Z, CERT-In %) |
| GET | `/api/results/{id}` | the full `result.json` (`{id}` can be the scan id or its folder name, like `zoo`) |
| POST | `/api/results/{id}/recompute` | body `{"z_year": 2032, "engineers": 2, "months": 3, "profile": "cii"}`; returns the re-scored result (nothing saved) |
| GET | `/api/results/{id}/cbom` · `/cbom.sig` · `/vex` · `/sarif` · `/csv` | download each format |
| GET | `/api/results/{id}/report.html` · `/report.pdf` · `/summary.md` | reports |
| POST | `/api/scan` | start a scan: body `{"config_yaml": "...yaml text..."}` or `{"config": {...}}`; returns `{"id": ...}` |
| GET | `/api/scan/{id}/status` | `running` / `done` / `error`, with a log |

Example:

```powershell
curl http://127.0.0.1:8787/api/health
curl -X POST http://127.0.0.1:8787/api/results/zoo/recompute -H "Content-Type: application/json" -d "{\"z_year\": 2032}"
```

> The API has **no login** and allows any origin. Keep it on `127.0.0.1` (the default) unless you're on a trusted
> network.

---

## Part 14: Optional extra engines

ECDAT's own Python engines do all the work. These external tools add a **second opinion**: when two engines agree,
confidence goes up. ECDAT looks for them in the repo's `tools/` folder, in `%USERPROFILE%\go\bin`, on your PATH, or
in a folder named by the `ECDAT_TOOLS_DIR` environment variable. `ecdat tools` shows what it found.

| Engine | Adds | How to install |
|---|---|---|
| **OpenGrep** | 151 extra crypto code rules (from semgrep-rules, already in `tools/semgrep-crypto-rules/`) | Download from https://github.com/opengrep/opengrep/releases and save as `tools/opengrep.exe` |
| **Syft** | Deeper dependency/SBOM detection | Download from https://github.com/anchore/syft/releases and save as `tools/syft.exe` |
| **cbomkit-theia** (IBM) | Crypto detection inside folders and images | `go install github.com/cbomkit/cbomkit-theia@latest` |
| **crane** | Pull images straight from a registry | `go install github.com/google/go-containerregistry/cmd/crane@latest` |
| **tshark** (Wireshark) | Cross-checks pcap parsing | Install Wireshark (Windows: it's found at `C:\Program Files\Wireshark`) |
| **CryptoLyzer** | Full TLS/SSH server analysis | Already installed (a Python package) |

To switch them all off for one run: `--no-external-tools`, or set `ECDAT_NO_EXTERNAL_TOOLS=1`.

### All environment variables

| Variable | Effect |
|---|---|
| `ECDAT_TOOLS_DIR` | Extra folder to look for opengrep/syft and rules |
| `ECDAT_NO_EXTERNAL_TOOLS=1` | Never call external engines |
| `ECDAT_NET_TIMEOUT` | Seconds to wait for live servers (default 8) |
| `ECDAT_RECORD_SVG=file.svg` | Save the scan session as an SVG image |

Set them in PowerShell with `$env:NAME="value"`, or on macOS/Linux with `export NAME=value`.

---

## Part 15: Running the tests

```powershell
python -m pytest -q -p no:warnings
```

Result on the tested setup: **92 tests: 90 passed, 2 skipped** (the skipped ones need optional engines that weren't
installed). Many tests use the zoo files, so run `ecdat zoo build` first.

Run one file or one test:

```powershell
python -m pytest tests/test_risk.py -q
python -m pytest tests/test_gate.py -q -k policy
```

The test files are named after what they test: `test_source.py`, `test_certificate.py`, `test_binary.py`,
`test_container.py`, `test_dependency.py`, `test_protocol.py`, `test_pcap.py`, `test_opengrep.py`, `test_normalize.py`,
`test_enrich.py`, `test_context.py`, `test_risk.py`, `test_plan.py`, `test_export.py`, `test_gate.py`, `test_api.py`,
`test_pipeline.py`, `test_evaluation.py`, `test_knowledge.py`, `test_model.py`.

---

## Part 16: Running with no internet (air-gapped)

ECDAT needs no internet at scan time: the knowledge base, schemas and rules ship inside it, and signing keys are made
locally. To install on an offline machine, prepare on a connected machine with the **same OS and Python version**:

```powershell
python -m pip download -d wheelhouse cryptography cyclonedx-python-lib lief scapy "tree-sitter>=0.25" tree-sitter-python tree-sitter-javascript tree-sitter-java tree-sitter-go tree-sitter-c yara-python fastapi "uvicorn[standard]" pyyaml typer rich jsonschema reportlab dilithium-py kyber-py httpx python-multipart cryptolyzer pycryptodomex pyasn1 pyasn1-modules javaobj-py3 pyjks
python -m pip wheel . -w wheelhouse --no-deps
cd web; npm ci; npm run build; cd ..          # so web/dist exists
```

Copy the whole repo folder (including `wheelhouse/`, `tools/` and `web/dist/`) to the offline machine, then:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --no-index --find-links wheelhouse ecdat
.\.venv\Scripts\python -m pip install --no-index --find-links wheelhouse --no-deps pyjks
.\.venv\Scripts\ecdat tools
```

The only things that ever touch a network are optional: probing `endpoints` targets (only the hosts you list) and
`crane` registry pulls (use image tar files instead). More detail: `docs/AIRGAP_INSTALL.md`.

---

## Part 17: A 3-minute demo script for the presentation

**Before you present:**

1. `ecdat zoo build` (once).
2. `ecdat scan -c tests/fixtures/zoo/ecdat.yaml -o out/zoo`
3. Build the dashboard (`cd web; npm ci; npm run build; cd ..`).
4. Start `ecdat serve out` and open http://127.0.0.1:8787 in a browser tab.
5. Keep the online version open in another tab as a backup: https://sarthakshrivastav-a.github.io/ecdat/dashboard
6. Have a terminal ready in the `ecdat` folder, with the environment activated.

**The flow:**

| Time | Do | Say |
|---|---|---|
| 0:00 | Nothing yet | "RSA and ECC protect UPI, Aadhaar and banking. A quantum computer will break them, and data stolen today can be decrypted later. India wants critical systems quantum-safe by 2029, but first you must know where your crypto is." |
| 0:20 | Run `ecdat scan -c tests/fixtures/zoo/ecdat.yaml -o out/zoo-live` | Point at the five phases. "Eleven targets, code in five languages, certificates, binaries, a container, network captures. 636 findings become 197 assets, in one signed CycloneDX 1.7 CBOM." |
| 0:50 | Dashboard → **Assets**, filter **RSA**, open one | "Every finding shows the exact file and line. If several engines agree, confidence goes up." |
| 1:20 | Dashboard → **Matrix** | "Risk against how hard the fix is. Top-left is slow, important work. Top-right is quick wins." |
| 1:50 | **Overview**, drag the **Z slider** from 2041 to 2032 | "Nobody knows when the quantum computer arrives, so you choose the year and see the effect live. Look, ALREADY EXPOSED appears." |
| 2:15 | **Plan**, change engineers 4 → 2 | "With fewer people the curve flattens, and the leftover list shows what won't be done in time." |
| 2:40 | Terminal: `ecdat verify out/zoo/cbom.json --pubkey out/keys/ecdat-mldsa65.pub`, then a live endpoint scan (Part 8, Example B) | "The CBOM is signed with a post-quantum signature, so it can't be faked. And we don't just read code: we ask the live server, which here already uses ML-KEM." |
| 3:00 | Show the Atlas page | "We ran it on 109 real codebases, and every result is public and verifiable." |

**Likely questions:**

- *"Is binary scanning reliable?"* It's honest about it: binary findings are labelled best-effort and capped at
  medium confidence, because they prove an algorithm is present, not used.
- *"How accurate is it?"* `ecdat evaluate` gives precision 1.0 and recall 1.0 on the test estate (60 planted items).
  The truth file was written after inspecting the output, so it's a regression check, not a blind test. The Atlas
  shows real-world results.
- *"Where does 2041 come from?"* It's the expert-survey median, used as an **adjustable assumption**, not a prediction.
- *"Does it fix the code?"* No. It recommends a replacement and suggests patches with evidence, but never changes
  your code itself.

---

## Part 18: Advanced scripts (Atlas, India survey, website)

These are what produced the published evidence. **You don't need them to run or demo ECDAT.**

| Script | What it does | Command |
|---|---|---|
| `scripts/fetch_real.py` | Downloads pyjwt, python-jose, node-jsonwebtoken and paramiko as zip files | `python scripts/fetch_real.py out/real-src` |
| `scripts/inspect_result.py` | Quick readable digest of any `result.json` (great for live-server results) | `python scripts/inspect_result.py out/live/result.json` |
| `scripts/atlas.py` | The **CBOM Atlas**: scans ~100 public repos (resumable steps) | `python scripts/atlas.py verify` → `fetch` → `scan` → `aggregate` (or `run` for low-disk mode) |
| `scripts/atlas_aggregate.py` | Rolls the per-repo scans into Atlas totals | called by `atlas.py aggregate` |
| `scripts/atlas_audit.py` | Hand-audit a random sample to measure real-world precision | `python scripts/atlas_audit.py sample -n 60`, then `score` |
| `scripts/survey.py` | India quantum-readiness snapshot: one normal TLS visit to each site by sector, publishing **sector totals only** | `python scripts/survey.py` → `out/survey/` (makes real network connections; `hosts.csv` stays private) |
| `scripts/build_site.py` | Builds the GitHub Pages evidence site into `out/site/` (needs the Atlas, survey and real-world scans first) | `python scripts/build_site.py` |
| `scripts/build_zoo.py` | Same as `zoo build` | `python scripts/build_zoo.py` |
| `scripts/prepare_rules.py` | Makes OpenGrep rule IDs unique | `python scripts/prepare_rules.py` |
| `scripts/ui_smoke.py` | Opens the dashboard in a headless browser and saves screenshots | `pip install playwright && python -m playwright install chromium`, then `python scripts/ui_smoke.py http://127.0.0.1:8787 docs/screenshots` |
| `media/` | Re-records the demo video clips | see `media/README.md` |

The ready-made demo videos are in `media/clips/` (01 is the live scan, 03–06 the dashboard views, 07 the evidence site).

---

## Part 19: Troubleshooting

| Problem | Fix |
|---|---|
| `ecdat zoo build` → `zoo build needs a source checkout of ECDAT` | ECDAT was installed from a wheel/git URL rather than from a clone, so `scripts/build_zoo.py` isn't there. Clone the repo and install it with `pip install -e .` (Part 3), then run it from the repo root. |
| `'ecdat' is not recognized` / `command not found` | The environment isn't active. Activate it ([Part 3, Step 4](#step-4-turn-the-environment-on-activate-it)) or use `.\.venv\Scripts\ecdat`. |
| PowerShell: *running scripts is disabled* | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or don't activate and use the full path. |
| `requires a different Python: 3.10` / install errors | Use Python **3.11+**: `py -3.11 -m venv .venv` |
| `No module named pytest` | `python -m pip install pytest` (it's in the Part 3 install line and `requirements-ci.txt`; you may have skipped that line). |
| Yellow `WARNING: ... winpcap is not installed` / `No libpcap provider available` | Harmless. ECDAT reads pcap files itself and doesn't need live packet capture. To silence it, install Npcap (https://npcap.com). |
| `pyjks` install fails asking for a C compiler | Install it with `--no-deps` exactly as in Part 3. |
| `yara-python` or `lief` fails to install | Upgrade pip first (`python -m pip install --upgrade pip`). Make sure you're on 64-bit Python 3.11+, which has ready-made wheels. |
| Dashboard shows "Dashboard not built" | Run `cd web; npm ci; npm run build`, then restart `ecdat serve`. |
| `npm run build` fails on Node version | Install Node 20.19+ or 22.12+ (Vite 8 needs it). |
| Port 8787 already in use | `ecdat serve out --port 8790` (for `npm run dev`, the server must stay on 8787). |
| Dashboard is empty | `ecdat serve` must point at a folder that contains scan folders with `result.json` (for example `out`, not `out/zoo/report.html`). |
| Live endpoint shows `reachable: false` | Firewall, proxy or a wrong port. Try `$env:ECDAT_NET_TIMEOUT="20"`; check you can open the site in a browser. |
| A path in my config is "not found" | Paths are relative to the **YAML file's folder**. Use an absolute path to be sure. |
| `zoo build` skipped keystores / the Go binary | OpenSSL, `keytool` (Java JDK) or Go isn't installed. Optional: the scan still works, but `evaluate` may then report missing items. |
| `ecdat verify` exit 2 | There's no `cbom.json.mldsa65.sig` next to the CBOM (scan was run with `--no-sign`, or the file was moved alone). |
| Very slow scan | Large folders take longer; `--no-external-tools` skips the external engines; narrow with `collectors: [...]`. |

To start completely fresh, delete `out/` (results and keys) and `tests/fixtures/zoo/{bin,certs,images,pcaps}` (the
generated zoo files). All of these are git-ignored.

---

## Part 20: Where things live in the code

```
ecdat/
  cli.py                  all the `ecdat ...` commands
  config.py               reads the YAML config
  pipeline.py             runs the phases: collectors -> merge -> enrich -> risk -> plan -> outputs
  tui.py                  how the scan looks in the terminal
  gate.py                 the CI gate policies
  evaluation.py           precision / recall against the zoo truth
  tools.py                finds optional external engines
  model.py                data structures (asset, finding, scan params)
  collectors/             source, opengrep, dependency, certificate, binary, container, protocol, pcap
  normalize/              merge findings -> assets, CycloneDX 1.7 output, ML-DSA signing, CERT-In Table 9
  enrich/                 context (real use vs test/comment), exposure, data lifetime, agility
  risk/                   quantum class, Mosca tiers, framework deadlines (DST, NIST, CNSA 2.0, EU, UK)
  plan/                   PQC recommendations, budget optimiser (knapsack), VEX, patch suggestions
  export/                 SARIF, CSV, HTML, PDF
  api/server.py           the FastAPI server behind `ecdat serve`
  knowledge/*.yaml        ALL crypto knowledge: algorithms, library signatures, code patterns,
                          PQC replacements, data classes, frameworks (edit these, not the code)
  schemas/                CycloneDX 1.7 JSON schemas used for validation
web/                      React + Vite dashboard (src/views = Overview/Matrix/Assets/Plan)
tests/                    pytest tests; tests/fixtures/zoo = the test estate + truth.yaml
tools/                    findcrypt3 YARA rules, semgrep crypto rules; place opengrep.exe / syft.exe here
scripts/                  zoo builder, Atlas, survey, site builder, helpers
docs/                     REAL_RUNS.md, AIRGAP_INSTALL.md, DEMO_SCRIPT.md, screenshots
media/                    demo video clips and the scripts that recorded them
.github/workflows/        ecdat-gate.yml (CI template)
```

**To teach ECDAT a new algorithm or library, edit the YAML files in `ecdat/knowledge/`.** No code changes are needed.

---

## Part 21: Glossary

| Term | Plain meaning |
|---|---|
| **Cryptography** | Maths that keeps data secret (encryption) or proves who sent it (signatures) |
| **RSA / ECC** | Today's most common public-key cryptography, which a quantum computer will break |
| **Shor's algorithm** | The quantum algorithm that breaks RSA and ECC |
| **Grover's algorithm** | A quantum speed-up that halves symmetric strength (AES-128 becomes weak; AES-256 stays fine) |
| **CRQC / Q-Day** | A "cryptographically relevant quantum computer", and the day one exists |
| **Harvest now, decrypt later (HNDL)** | Stealing encrypted data today to decrypt it once a quantum computer exists |
| **PQC** | Post-quantum cryptography: new algorithms quantum computers can't break |
| **ML-KEM** (FIPS 203) | The standard post-quantum key exchange (formerly Kyber) |
| **ML-DSA** (FIPS 204) | The standard post-quantum signature (formerly Dilithium); ECDAT signs with ML-DSA-65 |
| **X25519MLKEM768** | A "hybrid" key exchange that combines classic X25519 with ML-KEM, so it's safe if either holds |
| **CBOM** | Cryptographic Bill of Materials: a list of all crypto in a system |
| **CycloneDX 1.7** | The international file format ECDAT uses for the CBOM |
| **CERT-In Table 9** | The fields India's CERT-In technical guidelines ask a CBOM to include |
| **Mosca's inequality** | `X + Y > Z`: if secrecy years + migration years exceed years to Q-Day, you're at risk |
| **Crypto-agility** | How easily you can swap one algorithm for another |
| **VEX** | Statements saying whether a finding actually affects you |
| **SARIF** | A standard format for code-scanning results (GitHub understands it) |
| **Collector** | One ECDAT scanner (for example source code, certificates, live servers) |
| **Tier** | ECDAT's verdict: EXPOSED, ACT_NOW, MONITOR or SAFE |
| **DST / NQM roadmap** | India's quantum-safe migration timeline: critical infrastructure by 2027/2028/2029 |
| **Engineer-week** | One person working for one week, the unit of the migration budget |
