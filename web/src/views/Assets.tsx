import { useMemo, useState } from 'react'
import type { Asset, Tier } from '../types'
import { TIERS, TIER_LABEL } from '../types'

interface Props {
  assets: Asset[]
  selected: Asset | null
  onSelect: (a: Asset) => void
  initialTier: Tier | 'all'
  onTierChange: (t: Tier | 'all') => void
}

const TYPES = ['all', 'algorithm', 'certificate', 'protocol', 'related-crypto-material'] as const

export default function Assets({ assets, selected, onSelect, initialTier, onTierChange }: Props) {
  const [type, setType] = useState<string>('all')
  const [comp, setComp] = useState<string>('all')
  const [conf, setConf] = useState<string>('all')
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<'priority' | 'name' | 'agility'>('priority')
  const comps = useMemo(() => Array.from(new Set(assets.map((a) => a.component))).sort(), [assets])
  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase()
    const out = assets.filter((a) =>
      (initialTier === 'all' || a.risk?.tier === initialTier) &&
      (type === 'all' || a.asset_type === type) &&
      (comp === 'all' || a.component === comp) &&
      (conf === 'all' || a.confidence === conf) &&
      (!ql || `${a.name} ${a.component} ${a.family ?? ''} ${a.evidence.map((e) => e.location).join(' ')}`.toLowerCase().includes(ql)),
    )
    out.sort((a, b) => {
      if (sort === 'name') return a.name.localeCompare(b.name)
      if (sort === 'agility') return (a.agility?.total ?? 0) - (b.agility?.total ?? 0)
      return (b.risk?.priority ?? 0) - (a.risk?.priority ?? 0)
    })
    return out
  }, [assets, initialTier, type, comp, conf, q, sort])

  return (
    <section className="panel">
      <div className="row between" style={{ flexWrap: 'wrap', marginBottom: 'var(--s3)' }}>
        <h2 style={{ margin: 0 }}>Findings · every asset with its evidence</h2>
        <span className="status mono">{rows.length} shown <span className="dim">of {assets.length}</span></span>
      </div>
      <div className="filters">
        <select value={initialTier} onChange={(e) => onTierChange(e.target.value as Tier | 'all')}>
          <option value="all">all tiers</option>
          {TIERS.map((t) => <option key={t} value={t}>{TIER_LABEL[t]}</option>)}
        </select>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {TYPES.map((t) => <option key={t} value={t}>{t === 'all' ? 'all types' : t}</option>)}
        </select>
        <select value={comp} onChange={(e) => setComp(e.target.value)}>
          <option value="all">all components</option>
          {comps.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={conf} onChange={(e) => setConf(e.target.value)}>
          <option value="all">any confidence</option>
          <option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
        </select>
        <select value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}>
          <option value="priority">sort: priority</option><option value="agility">sort: hardest first</option><option value="name">sort: name</option>
        </select>
        <input
          type="search"
          aria-label="search assets"
          placeholder="search name, component, location"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {q || type !== 'all' || comp !== 'all' || conf !== 'all' || initialTier !== 'all' ? (
          <button onClick={() => { setQ(''); setType('all'); setComp('all'); setConf('all'); onTierChange('all') }}>clear</button>
        ) : null}
      </div>
      <div className="table-wrap">
      <table className="findings">
        <thead>
          <tr>
            <th>tier</th><th>asset</th><th>type</th><th>component</th><th>where</th>
            <th className="num" title="years the data must stay secret">X</th>
            <th className="num" title="years to change it">Y</th>
            <th className="num" title="0 rigid, 100 a config flag">agil</th>
            <th className="num">prio</th><th>replace with</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <tr
              key={a.bom_ref}
              className={selected?.bom_ref === a.bom_ref ? 'selected' : ''}
              onClick={() => onSelect(a)}
              tabIndex={0}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(a) } }}
            >
              <td>{a.risk ? <span className={`badge tier-${a.risk.tier}`}>{a.risk.tier}</span> : null}</td>
              <td className="nw">
                <span className="nm">
                  <i className={`cdot conf-${a.confidence}`} title={`${a.confidence} confidence`} />
                  <b>{a.name}</b>
                  {a.key_size ? <span className="mono muted">-{a.key_size}</span> : null}
                  {a.mode ? <span className="dim mono">{a.mode}</span> : null}
                </span>
              </td>
              <td className="muted nw" title={`${a.asset_type}${a.primitive ? ' · ' + a.primitive : ''}`}>
                {a.primitive || a.asset_type}
              </td>
              <td className="nw">{a.component}</td>
              <td className="mono small muted">
                <span className="loc" title={`${a.evidence[0]?.location ?? ''}${a.evidence[0]?.line ? ':' + a.evidence[0].line : ''}`}>
                  {a.evidence[0]?.location}{a.evidence[0]?.line ? `:${a.evidence[0].line}` : ''}
                </span>
                {a.evidence.length > 1 ? <span className="dim"> +{a.evidence.length - 1}</span> : null}
              </td>
              <td className="num">{a.risk?.x ?? '-'}</td>
              <td className="num">{a.risk?.y ?? '-'}</td>
              <td className="num">{a.agility?.total ?? '-'}</td>
              <td className="num">{a.risk?.priority ?? '-'}</td>
              <td className="mono small nw">{a.recommendation?.target ?? <span className="dim">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
      {rows.length === 0 ? <div className="empty" style={{ marginTop: 'var(--s3)' }}>no assets match these filters</div> : null}
      <div className="small dim" style={{ marginTop: 'var(--s3)' }}>
        X = years the data must stay secret · Y = years to change it · agility 0 is rigid, 100 is a config flag.
        The dot before each name is confidence: green high, amber medium, grey low. Click a row for its evidence.
      </div>
    </section>
  )
}
