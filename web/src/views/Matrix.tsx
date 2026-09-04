import { useMemo, useState } from 'react'
import type { Asset } from '../types'
import { TIERS, TIER_COLOR, TIER_LABEL } from '../types'

interface Props {
  assets: Asset[]
  onSelect: (a: Asset) => void
}

const W = 900
const H = 480
const PAD = { l: 56, r: 24, t: 24, b: 44 }

/** Risk x agility 2x2. x = agility.total (0 = rigid, left; 100 = agile, right). y = risk priority. */
export default function Matrix({ assets, onSelect }: Props) {
  const [hideSafe, setHideSafe] = useState(true)
  const [hover, setHover] = useState<Asset | null>(null)
  const pts = useMemo(
    () => assets.filter((a) => a.risk && a.agility && (!hideSafe || a.risk.tier !== 'SAFE')),
    [assets, hideSafe],
  )
  const maxP = Math.max(1, ...pts.map((a) => a.risk!.priority))
  const iw = W - PAD.l - PAD.r
  const ih = H - PAD.t - PAD.b
  const x = (a: Asset) => PAD.l + (a.agility!.total / 100) * iw
  const y = (a: Asset) => PAD.t + ih - (a.risk!.priority / maxP) * ih
  const midY = PAD.t + ih / 2
  const midX = PAD.l + iw / 2
  const quadrant = (dx: number, dy: number, label: string, sub: string) => (
    <g>
      <text x={dx} y={dy} style={{ fill: 'var(--amber)', fontSize: 12, fontWeight: 600 }}>{label}</text>
      <text x={dx} y={dy + 14} style={{ fontSize: 10 }}>{sub}</text>
    </g>
  )
  return (
    <div className="panel">
      <div className="row between">
        <h2 style={{ margin: 0 }}>Risk x crypto-agility</h2>
        <label className="small muted"><input type="checkbox" checked={hideSafe} onChange={(e) => setHideSafe(e.target.checked)} /> hide SAFE</label>
      </div>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="risk versus agility scatter">
        <rect x={PAD.l} y={PAD.t} width={iw} height={ih} fill="#06111f" stroke="var(--line)" />
        <line x1={midX} x2={midX} y1={PAD.t} y2={PAD.t + ih} stroke="var(--line-2)" strokeDasharray="4 4" />
        <line x1={PAD.l} x2={PAD.l + iw} y1={midY} y2={midY} stroke="var(--line-2)" strokeDasharray="4 4" />
        {quadrant(PAD.l + 10, PAD.t + 18, 'START PLANNING NOW', 'high risk, hard to change')}
        {quadrant(midX + 10, PAD.t + 18, 'DO THIS NOW', 'high risk, easy to change')}
        {quadrant(PAD.l + 10, midY + 18, 'LEAVE IT', 'low risk, hard to change')}
        {quadrant(midX + 10, midY + 18, 'CHEAP WINS', 'low risk, easy to change')}
        <text x={PAD.l} y={H - 12}>hard to change (agility 0)</text>
        <text x={PAD.l + iw} y={H - 12} textAnchor="end">easy to change (agility 100)</text>
        <text x={12} y={PAD.t + 10} transform={`rotate(-90 12 ${PAD.t + 10})`} textAnchor="end">risk priority</text>
        <text x={PAD.l - 6} y={PAD.t + 4} textAnchor="end">{maxP.toFixed(1)}</text>
        <text x={PAD.l - 6} y={PAD.t + ih} textAnchor="end">0</text>
        {pts.map((a) => (
          <circle
            key={a.bom_ref}
            cx={x(a)}
            cy={y(a)}
            r={hover === a ? 8 : 5.5}
            fill={TIER_COLOR[a.risk!.tier]}
            fillOpacity={0.85}
            stroke={hover === a ? '#fff' : '#06111f'}
            strokeWidth={1}
            style={{ cursor: 'pointer' }}
            onMouseEnter={() => setHover(a)}
            onMouseLeave={() => setHover(null)}
            onClick={() => onSelect(a)}
          >
            <title>{`${a.name}${a.key_size ? '-' + a.key_size : ''} · ${a.component} · ${TIER_LABEL[a.risk!.tier]} · priority ${a.risk!.priority} · agility ${a.agility!.total}`}</title>
          </circle>
        ))}
        {hover ? (
          <g>
            <rect x={Math.min(x(hover) + 10, W - 300)} y={Math.max(y(hover) - 40, PAD.t)} width={290} height={34} rx={4} fill="#0b1c31" stroke="var(--line-2)" />
            <text x={Math.min(x(hover) + 18, W - 292)} y={Math.max(y(hover) - 40, PAD.t) + 14} style={{ fill: 'var(--text)' }}>
              {hover.name}{hover.key_size ? `-${hover.key_size}` : ''} · {hover.component}
            </text>
            <text x={Math.min(x(hover) + 18, W - 292)} y={Math.max(y(hover) - 40, PAD.t) + 28}>
              {TIER_LABEL[hover.risk!.tier]} · priority {hover.risk!.priority} · agility {hover.agility!.total} · ~{hover.agility!.y_years}y
            </text>
          </g>
        ) : null}
      </svg>
      <div className="legend">
        {TIERS.map((t) => (<span key={t}><i style={{ background: TIER_COLOR[t] }} />{TIER_LABEL[t]}</span>))}
        <span className="dim">{pts.length} assets plotted · click a dot for evidence and the recommendation</span>
      </div>
    </div>
  )
}
