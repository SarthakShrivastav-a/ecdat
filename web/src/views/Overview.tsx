import type { Asset, ScanResult, Tier } from '../types'
import { DST_MILESTONES, TIERS, TIER_LABEL } from '../types'

interface Props {
  result: ScanResult
  onTier: (t: Tier) => void
}

function tierCounts(assets: Asset[], stats: ScanResult['stats']): Record<Tier, number> {
  if (stats.tiers) return stats.tiers
  const c: Record<Tier, number> = { EXPOSED: 0, ACT_NOW: 0, MONITOR: 0, SAFE: 0 }
  for (const a of assets) if (a.risk) c[a.risk.tier] += 1
  return c
}

export default function Overview({ result, onTier }: Props) {
  const { assets, params, stats } = result
  const tiers = tierCounts(assets, stats)
  const prof = DST_MILESTONES[params.profile] || DST_MILESTONES.enterprise
  const m2 = assets.filter((a) => a.risk?.overlays?.some((o) => o.rule.startsWith('M2') && o.status === 'violation')).length
  const m3 = assets.filter((a) => a.risk?.overlays?.some((o) => o.rule.startsWith('M3') && o.status === 'violation')).length
  const pq = assets.filter((a) => a.risk?.quantum_class === 'safe' && a.context?.usage !== 'non-security').length
  const certin = stats.certin
  const per = stats.collectors?.per_collector || {}
  const maxPer = Math.max(1, ...Object.values(per))
  const exposed = assets.filter((a) => a.risk?.tier === 'EXPOSED')
  const external = assets.filter((a) => a.exposure?.zone === 'external' && a.risk && a.risk.tier !== 'SAFE').length
  const hndl = stats.hndl_applicable ?? assets.filter((a) => a.risk?.hndl_applicable).length

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid cols-4">
        {TIERS.map((t) => (
          <div key={t} className={`panel tier-card ${t}`} onClick={() => onTier(t)} title="open in Assets">
            <h2>{TIER_LABEL[t]}</h2>
            <div className="big">{tiers[t] ?? 0}</div>
            <div className="sub">
              {t === 'EXPOSED' && 'data captured today outlives the migration (X + Y > Z)'}
              {t === 'ACT_NOW' && 'broken today, or a deadline lands inside the migration window'}
              {t === 'MONITOR' && 'quantum-vulnerable but short-lived, signing-only, or ample time'}
              {t === 'SAFE' && 'quantum-safe, or not a security control'}
            </div>
          </div>
        ))}
      </div>

      <div className="grid cols-3">
        <div className="panel">
          <h2>Harvest now, decrypt later</h2>
          <div className="big">{hndl}</div>
          <div className="sub">confidentiality assets an adversary can record today · {external} externally exposed and not safe</div>
          <div className="sub" style={{ marginTop: 10 }}>
            Z = <span className="mono" style={{ color: 'var(--amber-2)' }}>{params.z_year}</span> ({params.z_year - params.now_year} years). This is a user assumption, not a forecast.
          </div>
        </div>

        <div className="panel">
          <h2>DST / NQM roadmap · profile {params.profile.toUpperCase()}</h2>
          <div className="milestone">
            <span className="m">M1</span>
            <span>Inventory + quantum risk assessment, CBOM adopted<div className="cnt">{assets.length} assets inventoried in CycloneDX 1.7 · Table 9 completeness {certin?.overall_pct ?? '-'}%</div></span>
            <span className="yr">{prof.M1}</span>
          </div>
          <div className="milestone">
            <span className="m">M2</span>
            <span>No new classical-only deployments<div className="cnt">{m2} external classical-only assets the CI gate would block</div></span>
            <span className="yr">{prof.M2}</span>
          </div>
          <div className="milestone">
            <span className="m">M3</span>
            <span>Quantum-safe-only trust chains<div className="cnt">{m3} assets must migrate · {pq} already quantum-safe</div></span>
            <span className="yr">{prof.M3}</span>
          </div>
        </div>

        <div className="panel">
          <h2>CERT-In v2.0 Table 9 completeness</h2>
          <div className="big">{certin?.overall_pct != null ? `${certin.overall_pct}%` : '-'}</div>
          <div className="sub">minimum elements per cryptographic asset (CERT-In BOM guidelines, 9 Jul 2025, section 8.3)</div>
          <div style={{ marginTop: 10 }}>
            {certin && Object.entries(certin.by_type).map(([k, v]) => (
              <div className="dim-bar" key={k}>
                <span className="muted">{k} ({certin.counts?.[k] ?? 0})</span>
                <div className={`bar ${v >= 90 ? 'safe' : ''}`}><i style={{ width: `${v}%` }} /></div>
                <span className="mono dim">{Math.round(v)}</span>
              </div>
            ))}
            {certin?.top_missing?.length ? (
              <div className="small muted" style={{ marginTop: 6 }}>most missing: {certin.top_missing.slice(0, 3).map(([k, n]) => `${k} (${n})`).join(', ')}</div>
            ) : null}
          </div>
        </div>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <h2>Collector coverage</h2>
          {Object.keys(per).length === 0 ? <div className="muted small">no collector stats in this result</div> : null}
          {Object.entries(per).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
            <div className="dim-bar" key={k}>
              <span className="muted">{k}</span>
              <div className="bar"><i style={{ width: `${(100 * v) / maxPer}%` }} /></div>
              <span className="mono dim">{v}</span>
            </div>
          ))}
          {stats.collectors?.errors?.length ? (
            <div className="small muted" style={{ marginTop: 6 }}>{stats.collectors.errors.length} collector error(s) recorded in stats</div>
          ) : null}
          <div className="note" style={{ marginTop: 10 }}>
            <b>Honesty notes.</b> Binary findings (YARA constants, symbols, version strings) prove presence, not use, and are capped at medium confidence.
            Findings marked <i>library capability only</i> come from dependency manifests and are low confidence until a call site is seen.
          </div>
        </div>

        <div className="panel">
          <h2>Already exposed · what migration alone cannot save</h2>
          {exposed.length === 0 ? <div className="muted small">nothing in this tier at Z = {params.z_year}. Drag Z earlier to stress-test.</div> : null}
          <table>
            <thead><tr><th>asset</th><th>component</th><th className="num">X + Y</th><th className="num">Z</th><th className="num">priority</th></tr></thead>
            <tbody>
              {exposed.slice(0, 8).map((a) => (
                <tr key={a.bom_ref} onClick={() => onTier('EXPOSED')}>
                  <td>{a.name}{a.key_size ? `-${a.key_size}` : ''}</td>
                  <td className="muted">{a.component}</td>
                  <td className="num">{a.risk ? (a.risk.x + a.risk.y).toFixed(1) : '-'}</td>
                  <td className="num">{a.risk?.z}</td>
                  <td className="num">{a.risk?.priority}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="small muted" style={{ marginTop: 8 }}>For these, consider re-keying, shortening retention or accepting the loss, in addition to migrating.</div>
        </div>
      </div>
    </div>
  )
}
