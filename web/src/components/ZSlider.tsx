import { useEffect, useState } from 'react'
import { Z_PRESETS } from '../types'

interface Props {
  zYear: number
  nowYear: number
  busy: boolean
  onChange: (zYear: number) => void
}

/** Global "years until a cryptographically relevant quantum computer" control. Z is an assumption, never a fact. */
export default function ZSlider({ zYear, nowYear, busy, onChange }: Props) {
  const [local, setLocal] = useState(zYear)
  useEffect(() => setLocal(zYear), [zYear])
  const commit = (y: number) => {
    setLocal(y)
    if (y !== zYear) onChange(y)
  }
  return (
    <div className="zslider" title="Z = year a cryptographically relevant quantum computer is assumed to exist. Drag it: tiers recompute live.">
      <span className="muted small">Z (CRQC year)</span>
      <input
        type="range"
        min={2028}
        max={2050}
        step={1}
        value={local}
        disabled={busy}
        onChange={(e) => setLocal(Number(e.target.value))}
        onMouseUp={() => commit(local)}
        onTouchEnd={() => commit(local)}
        onKeyUp={() => commit(local)}
      />
      <span className="year">{local}</span>
      <span className="dim small mono">({local - nowYear}y)</span>
      <span className="presets">
        {Z_PRESETS.map((p) => (
          <button key={p.key} className={zYear === p.year ? 'active' : ''} disabled={busy} onClick={() => commit(p.year)} title={p.label}>
            {p.key}
          </button>
        ))}
      </span>
    </div>
  )
}
