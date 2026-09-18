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

  if (!result) return <div className="center">loading ECDAT results...</div>

  const openTier = (t: Tier) => { setTierFilter(t); setView('assets') }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <h1>EC<span>DAT</span></h1>
          <small>Enterprise Cryptographic Discovery &amp; Analysis · CBOM analytics</small>
          <span className="badge amber">PROTOTYPE</span>
          {source === 'mock' ? <span className="badge red">MOCK DATA</span> : null}
          {source === 'static' ? <span className="badge amber" title="Real ECDAT scans, precomputed at the Z presets; no server">STATIC DEMO · real scans</span> : null}
        </div>
        <nav className="tabs">
          {(['overview', 'matrix', 'assets', 'plan'] as View[]).map((v) => (
            <button key={v} className={view === v ? 'active' : ''} onClick={() => setView(v)}>{v}</button>
          ))}
        </nav>
        <div className="spacer" />
        <ZSlider zYear={result.params.z_year} nowYear={result.params.now_year} busy={busy} onChange={(z) => applyParams({ z_year: z })} />
        <select
          value={result.params.profile}
          disabled={busy}
          onChange={(e) => applyParams({ profile: e.target.value })}
          title="DST roadmap profile: CII deadlines 2027/2028/2029, enterprise 2028/2030/2033"
        >
          <option value="cii">profile: CII</option>
          <option value="enterprise">profile: enterprise</option>
        </select>
        {available.length > 1 ? (
          <select value={result.id} disabled={busy} onChange={(e) => switchScan(e.target.value)}>
            {available.map((s) => <option key={s.id} value={s.id}>{s.name} · {s.timestamp?.slice(0, 16)}</option>)}
          </select>
        ) : null}
        <Export id={result.id} disabled={source === 'mock'} />
      </header>

      <main className="main">
        <div className="row between" style={{ marginBottom: 12, flexWrap: 'wrap' }}>
          <span className="status">
            scan <b className="mono">{result.name}</b> · {result.assets.length} assets · {result.components.length} components · {result.timestamp?.slice(0, 19).replace('T', ' ')}
            {busy ? ' · recomputing...' : ''}
          </span>
          {error ? <span className="status" style={{ color: 'var(--act)' }}>{error}</span> : null}
        </div>
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
      </main>

      <footer className="footer">
        ECDAT static prototype for SIH 2026 PS 26164 (NTRO). Z is a user assumption anchored to the Global Risk Institute 2025 timeline report, not a forecast.
        Binary findings are best-effort. Mosca's inequality is applied only to confidentiality primitives; signatures and hashes are deadline-driven.
        Tool versions: {Object.entries(result.tool_versions || {}).filter(([, v]) => v).map(([k, v]) => `${k} ${String(v).slice(0, 24)}`).join(' · ') || 'n/a'}
      </footer>

      {selected ? <Drawer asset={selected} onClose={() => setSelected(null)} /> : null}
    </div>
  )
}
