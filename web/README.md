# ECDAT dashboard (web/)

Vite + React + TypeScript, no UI library, hand-written SVG charts. Dark "bridge at night" style: navy, one amber accent,
IBM Plex Sans/Mono.

## UI versions

The look is versioned in git so any of it can be rolled back without touching the analysis code:

| version | where | what it is |
| --- | --- | --- |
| `ui-v1` (tag) | `git show ui-v1` | the first dashboard: four equal tier cards, uniform panel grid |
| `ui-v2` (tag, branch `ui-v2-frontend`) | current | verdict-first layout, one stacked tier ribbon, labelled control rail, instrument chrome |

```bash
git checkout ui-v1 -- web/src        # put the old UI back, keep everything else
git checkout ui-v2 -- web/src        # and forward again
git diff ui-v1 ui-v2 -- web/src      # read the whole change
```

Only files under `web/src` differ between the two, so a rollback cannot affect the scanners, the CBOM or the API.

## Run

```bash
cd web
npm install
npm run dev          # http://localhost:5181 ; /api is proxied to http://127.0.0.1:8787 (ecdat serve)
npm run build        # tsc -b && vite build -> web/dist (served at / by `ecdat serve out/`)
```

With no server reachable the app loads `src/mock/result.json` and shows a red MOCK DATA badge; recompute and
exports need the real server.

## Views

- **overview**: a verdict line (how many assets cannot wait at this Z) over one stacked tier ribbon
  (ALREADY EXPOSED / ACT NOW / MONITOR / SAFE) where every segment filters the assets view; then
  harvest-now-decrypt-later, the DST/NQM M1-M2-M3 panel for the selected profile, CERT-In v2.0 Table 9 completeness,
  collector coverage and the honesty notes.
- **matrix**: risk priority x crypto-agility 2x2 (left = hard to change). Click a dot for the drawer.
- **assets**: filter by tier / type / component / confidence, search, sort; drawer shows evidence file:line + snippet,
  crypto properties, exposure, agility dimensions with reasons, risk overlays, recommendation with deltas and patches.
- **plan**: engineers x months budget, ordered work list, cumulative risk curve, what does not fit.
- **Z slider** (control rail): presets 2032 / 2035 / 2041 or any year 2028..2050; POSTs
  `/api/results/{id}/recompute`. Counts roll and ribbon segments resize on the new answer.

## Interaction and accessibility

Keys `1`-`4` switch views, `Enter` opens the focused row, `Escape` closes the drawer. Tabs are a real
`role="tablist"`, the drawer is `aria-modal`, every control has a visible `:focus-visible` ring, and all animation is
disabled under `prefers-reduced-motion: reduce`.

For local development against real data rather than the mock, copy a built static bundle in:

```bash
cp -r ../out/site/dashboard/static public/static      # git-ignored; makes dev show "real scan · static"
```

## Data contract

`src/types.ts` mirrors `ecdat/model.py` (`ScanResult.to_dict()`), `risk/mosca.py` (tiers, summarize),
`plan/optimizer.py` (plan dict), `normalize/certin.py` (summary) and `risk/frameworks.py` (overlays).
Stats extras expected from the API: `stats.certin` (certin.summary) and `stats.collectors` (run_collectors stats).
