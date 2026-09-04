import type { Params, ResultSummary, ScanResult } from './types'

export type Source = 'api' | 'mock'

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

export async function listResults(): Promise<ResultSummary[]> {
  return get<ResultSummary[]>('/api/results')
}

export async function fetchResult(id: string): Promise<ScanResult> {
  return get<ScanResult>(`/api/results/${encodeURIComponent(id)}`)
}

/** Load the newest scan from the API; fall back to the bundled mock when the server is unreachable. */
export async function loadInitial(): Promise<{ result: ScanResult; source: Source; available: ResultSummary[] }> {
  try {
    const list = await listResults()
    if (list.length) {
      const newest = [...list].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))[0]
      const result = await fetchResult(newest.id)
      return { result, source: 'api', available: list }
    }
  } catch {
    /* fall through to mock */
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
  return `/api/results/${encodeURIComponent(id)}/${kind}`
}

export function paramsToBody(p: Params): RecomputeBody {
  return { z_year: p.z_year, engineers: p.engineers, months: p.months, profile: p.profile }
}
