import { useCallback, useEffect, useMemo, useState } from 'react'
import { fetchResult, loadInitial, paramsToBody, recompute, staticRecompute, type Source } from './api'
import Drawer from './components/Drawer'
import Export from './components/Export'
import ZSlider from './components/ZSlider'
import type { Asset, ResultSummary, ScanResult, Tier } from './types'
import Assets from './views/Assets'
import Matrix from './views/Matrix'
import Overview from './views/Overview'
import Plan from './views/Plan'

type View = 'overview' | 'matrix' | 'assets' | 'plan'

const VIEWS: { id: View; label: string; hint: string }[] = [
  { id: 'overview', label: 'overview', hint: 'the verdict at this Z' },
  { id: 'matrix', label: 'matrix', hint: 'risk against how hard each fix is' },
  { id: 'assets', label: 'assets', hint: 'every finding with its evidence' },
  { id: 'plan', label: 'plan', hint: 'what fits the budget, in order' },
]

export default function App() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const [source, setSource] = useState<Source>('mock')
  const [available, setAvailable] = useState<ResultSummary[]>([])
  const [view, setView] = useState<View>('overview')
  const [selected, setSelected] = useState<Asset | null>(null)
  const [tierFilter, setTierFilter] = useState<Tier | 'all'>('all')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadInitial().then(({ result, source, available }) => {
      setResult(result)
      setSource(source)
      setAvailable(available)
    })
  }, [])

  const applyParams = useCallback(async (patch: Partial<{ z_year: number; engineers: number; months: number; profile: string }>) => {
    if (!result) return
    const body = { ...paramsToBody(result.params), ...patch }
    setBusy(true)
    setError(null)
    try {
      if (source === 'api') {
        const r = await recompute(result.id, body)
        setResult(r)
      } else if (source === 'static') {
        const { result: r, note } = await staticRecompute(result.id, body)
        setResult(r)
        if (note) setError(note)
      } else {
        // mock mode: no server to recompute; only echo the parameter so the UI stays honest
        setResult({ ...result, params: { ...result.params, ...body }, stats: { ...result.stats, z_year: body.z_year } })
        setError('mock data: recompute needs a running ecdat server (ecdat serve out/)')
      }
    } catch (e) {
      setError(String(e))
    } finally {
      setBusy(false)
    }
  }, [result, source])

  const switchScan = async (id: string) => {
    setBusy(true)
    try {
      setResult(await fetchResult(id))
      setSelected(null)
    } finally {
      setBusy(false)
    }
  }

  const byRef = useMemo(() => new Map((result?.assets ?? []).map((a) => [a.bom_ref, a])), [result])

  // keep the drawer pointing at the recomputed asset object
  useEffect(() => {
    if (selected && result) {
      const fresh = byRef.get(selected.bom_ref)
      if (fresh && fresh !== selected) setSelected(fresh)
    }
  }, [result, byRef, selected])

  // Escape closes the drawer; 1-4 switch views when not typing
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement
      const typing = el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement
      if (e.key === 'Escape') setSelected(null)
      if (!typing && e.key >= '1' && e.key <= '4') setView(VIEWS[Number(e.key) - 1].id)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  if (!result) {
    return (
      <div className="center">
        <div className="mono busy">reading ECDAT results…</div>
      </div>
    )
  }

  const openTier = (t: Tier) => { setTierFilter(t); setView('assets') }
  const versions = Object.entries(result.tool_versions || {}).filter(([, v]) => v)

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="tick" aria-hidden />
          <h1>EC<span>DAT</span></h1>
          <small>cryptographic discovery &amp; analysis</small>
          {source === 'mock' ? <span className="badge red"><i className="dot" />mock data</span> : null}
          {source === 'static' ? (
            <span className="badge amber" title="Real ECDAT scans, precomputed at the Z presets; no server needed">
              <i className="dot" />real scan · static
            </span>
          ) : null}
          {source === 'api' ? <span className="badge amber"><i className="dot" />live server</span> : null}
        </div>

        <nav className="tabs" role="tablist" aria-label="views">
          {VIEWS.map((v) => (
            <button
              key={v.id}
              role="tab"
              aria-selected={view === v.id}
              className={view === v.id ? 'active' : ''}
              onClick={() => setView(v.id)}
              title={v.hint}
            >
              {v.label}
            </button>
          ))}
        </nav>

        <div className="right">
          <span className="status mono" title="assets · components · when this scan ran">
            {result.assets.length} assets · {result.components.length} comp
          </span>
          <Export id={result.id} disabled={source === 'mock'} />
        </div>
      </header>

      <div className="rail">
        <div className="cell">
          <span className="lbl">quantum year (Z) — your assumption</span>
          <ZSlider zYear={result.params.z_year} nowYear={result.params.now_year} busy={busy} onChange={(z) => applyParams({ z_year: z })} />
        </div>
        <div className="cell">
          <label htmlFor="profile">roadmap profile</label>
          <select
            id="profile"
            value={result.params.profile}
            disabled={busy}
            onChange={(e) => applyParams({ profile: e.target.value })}
            title="DST roadmap profile: CII deadlines 2027/2028/2029, enterprise 2028/2030/2033"
          >
            <option value="cii">critical infrastructure</option>
            <option value="enterprise">enterprise</option>
          </select>
        </div>
        <div className="cell grow">
          <label htmlFor="scan">scan</label>
          {available.length > 1 ? (
            <select id="scan" value={result.id} disabled={busy} onChange={(e) => switchScan(e.target.value)}>
              {available.map((s) => <option key={s.id} value={s.id}>{s.name} · {s.timestamp?.slice(0, 16).replace('T', ' ')}</option>)}
            </select>
          ) : (
            <span className="mono small">{result.name} · {result.timestamp?.slice(0, 16).replace('T', ' ')}</span>
          )}
        </div>
        {busy || error ? (
          <div className="cell" style={{ justifyContent: 'flex-end' }}>
            {busy ? <span className="status mono busy">recomputing…</span> : null}
            {error ? <span className="status" style={{ color: 'var(--act)', maxWidth: 420 }}>{error}</span> : null}
          </div>
        ) : null}
      </div>

      <main className="main">
        <div key={view} className="stagger">
          {view === 'overview' ? <Overview result={result} onTier={openTier} /> : null}
          {view === 'matrix' ? <Matrix assets={result.assets} onSelect={setSelected} /> : null}
          {view === 'assets' ? (
            <Assets assets={result.assets} selected={selected} onSelect={setSelected} initialTier={tierFilter} onTierChange={setTierFilter} />
          ) : null}
          {view === 'plan' ? (
            <Plan
              plan={result.plan}
              engineers={result.params.engineers}
              months={result.params.months}
              busy={busy}
              onBudget={(engineers, months) => applyParams({ engineers, months })}
              onSelect={(ref) => { const a = byRef.get(ref); if (a) setSelected(a) }}
              assets={result.assets}
            />
          ) : null}
        </div>
      </main>

      <footer className="footer">
        <details>
          <summary>How to read this, and what it does not claim</summary>
          <p>
            Z is a user assumption anchored to the Global Risk Institute 2025 timeline report, not a forecast. Mosca's
            inequality is applied only to confidentiality primitives; signatures and hashes are deadline-driven. Binary
            findings prove presence, not use, and are capped at medium confidence. Findings that come only from a
            dependency manifest are capped at MONITOR until a call site is seen.
          </p>
          <p className="mono" style={{ fontSize: 10.5 }}>
            ECDAT prototype · SIH 2026 PS 26164 (NTRO) · {versions.map(([k, v]) => `${k} ${String(v).slice(0, 24)}`).join(' · ') || 'versions n/a'}
          </p>
        </details>
      </footer>

      {selected ? <Drawer asset={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  )
}
