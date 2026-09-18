import type { Params, ResultSummary, ScanResult } from './types'

export type Source = 'api' | 'static' | 'mock'

const TIMEOUT_MS = 6000

async function get<T>(url: string): Promise<T> {
  const ctl = new AbortController()
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS)
  try {
    const r = await fetch(url, { signal: ctl.signal })
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`)
    return (await r.json()) as T
  } finally {
    clearTimeout(t)
  }
}

export async function loadMock(): Promise<ScanResult> {
  const m = await import('./mock/result.json')
  return (m.default ?? m) as unknown as ScanResult
}

/* ---------- static mode (GitHub Pages): real scans, precomputed at the Z presets and both profiles ---------- */
interface StaticVariant { z_year: number; profile: string; engineers: number; months: number; file: string }
interface StaticScan extends ResultSummary { default: string; variants: StaticVariant[]; exports: Record<string, string> }
let staticScans: StaticScan[] | null = null

async function loadStaticIndex(): Promise<StaticScan[] | null> {
  try {
    const idx = await get<{ scans: StaticScan[] }>('./static/index.json')
    staticScans = idx.scans?.length ? idx.scans : null
  } catch {
    staticScans = null
  }
  return staticScans
}

const staticScan = (id: string) => staticScans?.find((s) => s.id === id)

/** Static-mode stand-in for the recompute endpoint: pick the precomputed variant, snapping Z to the nearest preset. */
export async function staticRecompute(id: string, body: RecomputeBody): Promise<{ result: ScanResult; note: string | null }> {
  const scan = staticScan(id)
  if (!scan) throw new Error('static demo: unknown scan')
  const base = scan.variants.find((v) => v.file === scan.default)!
  if (body.engineers !== base.engineers || body.months !== base.months) {
    throw new Error(`static demo: the plan is precomputed for ${base.engineers} engineers x ${base.months} months; install ECDAT locally to replan any budget`)
  }
  const pool = scan.variants.filter((v) => v.profile === body.profile)
  const pick = pool.reduce((a, b) => (Math.abs(b.z_year - body.z_year) < Math.abs(a.z_year - body.z_year) ? b : a))
  const result = await get<ScanResult>(`./static/${pick.file}`)
  const note = pick.z_year === body.z_year ? null
    : `static demo: Z snaps to the precomputed presets (${[...new Set(pool.map((v) => v.z_year))].join(' / ')}); a local install recomputes any year`
  return { result, note }
}

export async function listResults(): Promise<ResultSummary[]> {
  return get<ResultSummary[]>('/api/results')
}

export async function fetchResult(id: string): Promise<ScanResult> {
  const scan = staticScan(id)
  if (scan) return get<ScanResult>(`./static/${scan.default}`)
  return get<ScanResult>(`/api/results/${encodeURIComponent(id)}`)
}

/** Load the newest scan from the API; fall back to the bundled mock when the server is unreachable. */
export async function loadInitial(): Promise<{ result: ScanResult; source: Source; available: ResultSummary[] }> {
  // a static bundle next to the app wins (GitHub Pages); otherwise talk to `ecdat serve`
  const bundled = await loadStaticIndex()
  if (bundled) {
    return { result: await get<ScanResult>(`./static/${bundled[0].default}`), source: 'static', available: bundled }
  }
  try {
    const list = await listResults()
    if (list.length) {
      const newest = [...list].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))[0]
      const result = await fetchResult(newest.id)
      return { result, source: 'api', available: list }
    }
  } catch {
    /* no server and no static bundle: fall back to the built-in sample */
  }
  return { result: await loadMock(), source: 'mock', available: [] }
}

export interface RecomputeBody {
  z_year: number
  engineers: number
  months: number
  profile: string
}

export async function recompute(id: string, body: RecomputeBody): Promise<ScanResult> {
  const r = await fetch(`/api/results/${encodeURIComponent(id)}/recompute`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) throw new Error(`recompute: HTTP ${r.status}`)
  return (await r.json()) as ScanResult
}

export type ExportKind = 'cbom' | 'vex' | 'sarif' | 'csv' | 'report.html' | 'report.pdf'

export function exportUrl(id: string, kind: ExportKind): string {
  const scan = staticScan(id)
  if (scan) return scan.exports[kind] ? `./static/${scan.exports[kind]}` : '#'
  return `/api/results/${encodeURIComponent(id)}/${kind}`
}

export function paramsToBody(p: Params): RecomputeBody {
  return { z_year: p.z_year, engineers: p.engineers, months: p.months, profile: p.profile }
}
