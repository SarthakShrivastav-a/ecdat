import { useEffect, useState } from 'react'
import type { Asset, Plan as PlanT, PlanItem } from '../types'
import { TIER_LABEL } from '../types'

interface Props {
  plan: Partial<PlanT>
  engineers: number
  months: number
  busy: boolean
  onBudget: (engineers: number, months: number) => void
  onSelect: (bomRef: string) => void
  assets: Asset[]
}

const W = 900
const H = 260
const PAD = { l: 50, r: 20, t: 16, b: 36 }

function Curve({ items, capacity }: { items: PlanItem[]; capacity: number }) {
  const iw = W - PAD.l - PAD.r
  const ih = H - PAD.t - PAD.b
  const maxW = Math.max(capacity, ...items.map((i) => i.cumulative_weeks ?? 0), 1)
  const pts = [{ w: 0, p: 0 }, ...items.map((i) => ({ w: i.cumulative_weeks ?? 0, p: i.cumulative_risk_pct ?? 0 }))]
  const X = (w: number) => PAD.l + (w / maxW) * iw
  const Y = (p: number) => PAD.t + ih - (p / 100) * ih
  const d = pts.map((pt, i) => `${i ? 'L' : 'M'}${X(pt.w).toFixed(1)},${Y(pt.p).toFixed(1)}`).join(' ')
  return (
    <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="cumulative risk reduction">
      <rect x={PAD.l} y={PAD.t} width={iw} height={ih} fill="#06111f" stroke="var(--line)" />
      {[25, 50, 75, 100].map((p) => (
        <g key={p}>
          <line x1={PAD.l} x2={PAD.l + iw} y1={Y(p)} y2={Y(p)} stroke="var(--line)" strokeDasharray="3 5" />
          <text x={PAD.l - 6} y={Y(p) + 4} textAnchor="end">{p}%</text>
        </g>
      ))}
      <line x1={X(capacity)} x2={X(capacity)} y1={PAD.t} y2={PAD.t + ih} stroke="var(--amber)" strokeDasharray="4 4" />
      <text x={X(capacity) + 4} y={PAD.t + 12} style={{ fill: 'var(--amber)' }}>budget {capacity} eng-weeks</text>
      <path d={d} fill="none" stroke="var(--amber)" strokeWidth={2} />
      {pts.map((pt, i) => <circle key={i} cx={X(pt.w)} cy={Y(pt.p)} r={3} fill="var(--amber-2)" />)}
      <text x={PAD.l} y={H - 10}>0</text>
      <text x={PAD.l + iw} y={H - 10} textAnchor="end">{maxW.toFixed(0)} engineer-weeks</text>
    </svg>
  )
}

export default function Plan({ plan, engineers, months, busy, onBudget, onSelect, assets }: Props) {
  const [eng, setEng] = useState(engineers)
  const [mon, setMon] = useState(months)
  useEffect(() => { setEng(engineers); setMon(months) }, [engineers, months])
  const items = plan.items ?? []
  const uncovered = plan.uncovered ?? []
  const byRef = new Map(assets.map((a) => [a.bom_ref, a]))
  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="panel">
        <div className="row between" style={{ flexWrap: 'wrap' }}>
          <h2 style={{ margin: 0 }}>Migration plan under a budget</h2>
          <form className="row" onSubmit={(e) => { e.preventDefault(); onBudget(eng, mon) }}>
            <label className="small muted">engineers <input type="number" min={1} max={200} value={eng} onChange={(e) => setEng(Number(e.target.value))} /></label>
            <label className="small muted">months <input type="number" min={1} max={60} value={mon} onChange={(e) => setMon(Number(e.target.value))} /></label>
            <button className="primary" type="submit" disabled={busy}>{busy ? 'planning...' : 'replan'}</button>
          </form>
        </div>
        <div className="grid cols-4" style={{ marginTop: 12 }}>
          <div><div className="big">{plan.covered_pct ?? 0}%</div><div className="sub">of quantum risk removed within budget</div></div>
          <div><div className="big">{plan.used_weeks ?? 0}<span className="dim" style={{ fontSize: 16 }}>/{plan.capacity_weeks ?? 0}</span></div><div className="sub">engineer-weeks used / available</div></div>
          <div><div className="big">{items.length}<span className="dim" style={{ fontSize: 16 }}>/{plan.candidates ?? 0}</span></div><div className="sub">assets scheduled / candidates</div></div>
          <div><div className="big" style={{ color: (plan.exposed_remaining ?? 0) > 0 ? 'var(--exposed)' : 'var(--safe)' }}>{plan.exposed_remaining ?? 0}</div><div className="sub">ALREADY EXPOSED assets left outside the budget</div></div>
        </div>
        <Curve items={items} capacity={plan.capacity_weeks ?? 0} />
        <div className="small muted">Greedy knapsack by risk-per-engineer-week; certificates and configuration first on ties. Effort comes from the crypto-agility score, not a guess.</div>
      </div>

      <div className="panel">
        <h2>Ordered work list</h2>
        <table>
          <thead><tr><th>#</th><th>asset</th><th>component</th><th>tier</th><th>replace with</th><th className="num">effort (wk)</th><th className="num">risk / wk</th><th className="num">cum. weeks</th><th className="num">cum. risk</th></tr></thead>
          <tbody>
            {items.map((it, i) => (
              <tr key={it.bom_ref} onClick={() => byRef.has(it.bom_ref) && onSelect(it.bom_ref)}>
                <td className="num dim">{i + 1}</td>
                <td><b>{it.name}</b> <span className="dim small">{it.asset_type}</span><div className="mono small dim">{it.location}</div></td>
                <td>{it.component}</td>
                <td><span className={`badge tier-${it.tier}`}>{TIER_LABEL[it.tier]}</span></td>
                <td className="mono small">{it.target ?? '-'}</td>
                <td className="num">{it.effort_weeks}</td>
                <td className="num">{it.risk_per_week ?? '-'}</td>
                <td className="num">{it.cumulative_weeks}</td>
                <td className="num">{it.cumulative_risk_pct}%</td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 ? <div className="center">nothing to schedule: every asset is SAFE, or no plan in this result</div> : null}
      </div>

      {uncovered.length ? (
        <div className="panel">
          <h2>Does not fit this budget ({uncovered.length})</h2>
          <table>
            <thead><tr><th>asset</th><th>component</th><th>tier</th><th>replace with</th><th className="num">effort (wk)</th><th className="num">priority</th></tr></thead>
            <tbody>
              {uncovered.map((it) => (
                <tr key={it.bom_ref} onClick={() => byRef.has(it.bom_ref) && onSelect(it.bom_ref)}>
                  <td><b>{it.name}</b> <span className="dim small">{it.asset_type}</span></td>
                  <td>{it.component}</td>
                  <td><span className={`badge tier-${it.tier}`}>{TIER_LABEL[it.tier]}</span></td>
                  <td className="mono small">{it.target ?? '-'}</td>
                  <td className="num">{it.effort_weeks}</td>
                  <td className="num">{it.priority}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}
