# Demo footage

Eight clips, each recorded against the real tool and the real scans — nothing is mocked or
re-enacted. Regenerate any of them with the two scripts here.

| # | clip | length | what it shows |
|---|---|---|---|
| 01 | `clips/01-scan-live.mp4` | 64 s | A screen recording of an actual `ecdat scan` in its own console window: the command, then the DISCOVER table filling in collector by collector over four targets with every external engine running, RECONCILE, ANALYSE, the tier bars, the nine artefacts and the completion panel — 113 assets, 365 findings, CERT-In 75.5%, signed ML-DSA-65, 50.5 s. |
| 01b | `clips/01b-scan-live-2x.mp4` | 32 s | The same take at 2x, for a tighter edit. |
| 02 | `clips/02-scan-session.mp4` | 22 s | A slow pan down the full run **with** every external engine enabled (OpenGrep, Syft, cbomkit-theia, tshark): 9 collectors, 44 target runs, 639 findings, 197 assets, signed CBOM. |
| 03 | `clips/03-overview.mp4` | 12 s | The verdict — *11 of 159 assets cannot wait* — then the quantum year Z is dragged back and every tier recomputes live, with ALREADY EXPOSED appearing. |
| 04 | `clips/04-findings.mp4` | 13 s | Filtering the findings table to RSA, opening one, and reading the evidence behind it: file:line, call sites, agility dimensions, the recommended target. |
| 05 | `clips/05-matrix.mp4` | 12 s | Risk against how hard the fix is, hovering individual assets, then revealing the SAFE tier. |
| 06 | `clips/06-plan.mp4` | 10 s | Changing the budget from 4 engineers to 8 and re-planning: the cumulative risk curve and the ordered work list both change. |
| 07 | `clips/07-evidence.mp4` | 15 s | The published evidence site: the hub, then the CBOM Atlas, filtered by category, with every repository's CBOM, signature, report and VEX file. |

## Recording them again

```powershell
# 01 - a real console window, captured with ffmpeg and cropped to that window only
powershell -ExecutionPolicy Bypass -File media\record_terminal.ps1

# 02 - regenerate the session still, then pan it (see the ffmpeg line in the git history)
$env:ECDAT_RECORD_SVG="docs/screenshots/scan.svg"
ecdat scan -c tests/fixtures/zoo/ecdat.yaml -o out/demo

# 03-07 - the dashboard and the site, driven by Playwright
cd media; npm i; npx playwright install chromium
python -m http.server 8733 --directory ..\out\site      # in another shell
node record.js                                          # or: node record.js overview findings
```

`raw/` holds the unedited captures and is not committed. `record.js` drives a real browser at
1440x900, deviceScaleFactor 2, and moves the pointer deliberately so the footage is watchable.

One caution for anyone re-recording clip 01: it captures a rectangle of the desktop, so the console
window is parked at a fixed position and the capture is cropped to it. Check the tail of the file
before publishing — once the window closes, whatever is behind it becomes visible.
