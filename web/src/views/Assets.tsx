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
    <div className="panel">
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
        <input type="search" placeholder="search name, component, location" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="status">{rows.length} / {assets.length}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>tier</th><th>asset</th><th>type · primitive</th><th>component</th><th>where</th>
            <th className="num">X</th><th className="num">Y</th><th className="num">agility</th><th className="num">priority</th><th>target</th><th>conf</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.bom_ref} className={selected?.bom_ref === a.bom_ref ? 'selected' : ''} onClick={() => onSelect(a)}>
              <td>{a.risk ? <span className={`badge tier-${a.risk.tier}`}>{a.risk.tier}</span> : null}</td>
              <td><b>{a.name}</b>{a.key_size ? <span className="mono muted">-{a.key_size}</span> : null}{a.mode ? <span className="dim mono"> {a.mode}</span> : null}</td>
              <td className="muted">{a.asset_type}{a.primitive ? ` · ${a.primitive}` : ''}</td>
              <td>{a.component}</td>
              <td className="mono small muted">{a.evidence[0]?.location}{a.evidence[0]?.line ? `:${a.evidence[0].line}` : ''}{a.evidence.length > 1 ? ` +${a.evidence.length - 1}` : ''}</td>
              <td className="num">{a.risk?.x ?? '-'}</td>
              <td className="num">{a.risk?.y ?? '-'}</td>
              <td className="num">{a.agility?.total ?? '-'}</td>
              <td className="num">{a.risk?.priority ?? '-'}</td>
              <td className="mono small">{a.recommendation?.target ?? <span className="dim">-</span>}</td>
              <td><span className={`badge conf-${a.confidence}`}>{a.confidence}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length === 0 ? <div className="center">no assets match these filters</div> : null}
    </div>
  )
}
