import type { Tier } from '../types'
import { TIERS, TIER_COLOR, TIER_LABEL } from '../types'
import { useCountUp } from './useCountUp'

interface Props {
  tiers: Record<Tier, number>
  onTier: (t: Tier) => void
}

const BLURB: Record<Tier, string> = {
  EXPOSED: 'recorded today, readable later',
  ACT_NOW: 'broken now, or a deadline lands inside the migration',
  MONITOR: 'vulnerable but short-lived or signing-only',
  SAFE: 'quantum-safe, or not a security control',
}

/** One bar, four tiers. Segments carry the count and animate when Z moves; each one is a filter. */
export default function Ribbon({ tiers, onTier }: Props) {
  const total = Math.max(1, TIERS.reduce((s, t) => s + (tiers[t] ?? 0), 0))
  return (
    <div className="ribbon">
      <div className="track" role="group" aria-label="assets by tier">
        {TIERS.map((t) => {
          const n = tiers[t] ?? 0
          if (n === 0) return null
          return (
            <button
              key={t}
              className="seg"
              style={{ ['--c' as string]: TIER_COLOR[t], flexGrow: n }}
              onClick={() => onTier(t)}
              title={`${TIER_LABEL[t]}: ${n} of ${total} assets - ${BLURB[t]}`}
              aria-label={`${TIER_LABEL[t]}, ${n} assets`}
            >
              <span>{n / total > 0.05 ? n : ''}{n / total > 0.17 ? <small>{TIER_LABEL[t].toLowerCase()}</small> : null}</span>
            </button>
          )
        })}
      </div>
      <div className="keys">
        {TIERS.map((t) => (
          <button key={t} className={`key ${tiers[t] ? '' : 'off'}`} style={{ ['--c' as string]: TIER_COLOR[t] }} onClick={() => onTier(t)}>
            <i />
            <span>
              <b>{tiers[t] ?? 0}</b> {TIER_LABEL[t].toLowerCase()} <span className="dim">· {BLURB[t]}</span>
            </span>
          </button>
        ))}
      </div>
    </div>
  )
}

/** A single rolling number, for the verdict headline and the stat row. */
export function Rolling({ value }: { value: number }) {
  return <em>{useCountUp(value)}</em>
}
