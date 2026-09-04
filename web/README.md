# ECDAT dashboard (web/)

Vite + React + TypeScript, no UI library, hand-written SVG charts. Dark "bridge at night" style: navy, one amber accent,
IBM Plex Sans/Mono.

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

- **overview**: tier buckets (ALREADY EXPOSED / ACT NOW / MONITOR / SAFE), harvest-now-decrypt-later count, DST/NQM
  M1-M2-M3 panel for the selected profile, CERT-In v2.0 Table 9 completeness, collector coverage, honesty notes.
- **matrix**: risk priority x crypto-agility 2x2 (left = hard to change). Click a dot for the drawer.
- **assets**: filter by tier / type / component / confidence, search, sort; drawer shows evidence file:line + snippet,
  crypto properties, exposure, agility dimensions with reasons, risk overlays, recommendation with deltas and patches.
- **plan**: engineers x months budget, ordered work list, cumulative risk curve, what does not fit.
- **Z slider** (top bar): presets 2032 / 2035 / 2041 or any year 2028..2050; POSTs `/api/results/{id}/recompute`.

## Data contract

`src/types.ts` mirrors `ecdat/model.py` (`ScanResult.to_dict()`), `risk/mosca.py` (tiers, summarize),
`plan/optimizer.py` (plan dict), `normalize/certin.py` (summary) and `risk/frameworks.py` (overlays).
Stats extras expected from the API: `stats.certin` (certin.summary) and `stats.collectors` (run_collectors stats).
