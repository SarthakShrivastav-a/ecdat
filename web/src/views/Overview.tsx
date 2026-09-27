import Ribbon, { Rolling } from '../components/Ribbon'
import type { Asset, ScanResult, Tier } from '../types'
import { DST_MILESTONES } from '../types'

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
  const urgent = (tiers.EXPOSED ?? 0) + (tiers.ACT_NOW ?? 0)
  const years = params.z_year - params.now_year

  return (
    <div className="grid" style={{ gap: 'var(--s4)' }}>
      {/* the one anchor: what this scan actually decides, and the bar it decided it from */}
      <section className="verdict">
        <div>
          <div className="asof">verdict · {result.name} · Z = {params.z_year}</div>
          <h2 className="headline">
            <Rolling value={urgent} /> of {assets.length} assets
            <br />
            cannot wait <span className="q">— {(tiers.EXPOSED ?? 0) > 0 ? `${tiers.EXPOSED} already past saving` : 'none past saving yet'}</span>
          </h2>
          <p className="because">
            Assuming a quantum computer arrives in <b>{params.z_year}</b> ({years} years), <b>{hndl}</b> confidentiality
            assets can be recorded today and read then — <b>{external}</b> of them reachable from outside. Drag Z to
            stress-test the assumption; every tier below recomputes.
          </p>
        </div>
        <Ribbon tiers={tiers} onTier={onTier} />
      </section>

      <div className="grid cols-3">
        <section className="panel">
          <h2>Harvest now, decrypt later</h2>
          <div className="big">{hndl}</div>
          <div className="sub">
            confidentiality assets an adversary can record today and read once Z arrives. {external} are externally
            exposed and not safe.
          </div>
          <div className="statline" style={{ marginTop: 'var(--s5)' }}>
            <div className="stat"><span className="v">{params.z_year}</span><span className="k">assumed Z</span></div>
            <div className="stat"><span className="v">{years}y</span><span className="k">runway</span></div>
            <div className="stat"><span className="v">{exposed.length}</span><span className="k">past saving</span></div>
          </div>
          <div className="note" style={{ marginTop: 'var(--s4)' }}>
            Z is an <b>assumption you set</b>, not a forecast. Nothing here predicts when a quantum computer arrives.
          </div>
        </section>

        <section className="panel">
          <h2>DST / NQM roadmap · {params.profile === 'cii' ? 'critical infrastructure' : 'enterprise'}</h2>
          <div className="milestone">
            <span className={`m ${certin?.overall_pct ? 'done' : ''}`}>M1</span>
            <span className="t">
              Inventory and quantum risk assessment, CBOM adopted
              <div className="cnt">{assets.length} assets in CycloneDX 1.7 · Table 9 completeness {certin?.overall_pct ?? '—'}%</div>
            </span>
            <span className="yr">{prof.M1}<small>due</small></span>
          </div>
          <div className="milestone">
            <span className="m">M2</span>
            <span className="t">
              No new classical-only deployments
              <div className="cnt">{m2} external classical-only assets the CI gate would block today</div>
            </span>
            <span className="yr">{prof.M2}<small>due</small></span>
          </div>
          <div className="milestone">
            <span className="m">M3</span>
            <span className="t">
              Quantum-safe-only trust chains
              <div className="cnt">{m3} assets must migrate · {pq} already quantum-safe</div>
            </span>
            <span className="yr">{prof.M3}<small>due</small></span>
          </div>
        </section>

        <section className="panel">
          <h2>CERT-In v2.0 Table 9 completeness</h2>
          <div className="big">{certin?.overall_pct != null ? `${certin.overall_pct}%` : '—'}</div>
          <div className="sub">minimum elements per cryptographic asset (CERT-In BOM guidelines, 9 Jul 2025, §8.3)</div>
          <div style={{ marginTop: 'var(--s4)' }}>
            {certin && Object.entries(certin.by_type).map(([k, v]) => (
              <div className="dim-bar" key={k}>
                <span className="muted">{k} <span className="dim">({certin.counts?.[k] ?? 0})</span></span>
                <div className={`bar ${v >= 90 ? 'safe' : ''}`}><i style={{ width: `${v}%` }} /></div>
                <span className="mono dim">{Math.round(v)}</span>
              </div>
            ))}
            {certin?.top_missing?.length ? (
              <div className="small dim" style={{ marginTop: 'var(--s2)' }}>
                most missing: {certin.top_missing.slice(0, 3).map(([k, n]) => `${k} (${n})`).join(', ')}
              </div>
            ) : null}
          </div>
        </section>
      </div>

      <div className="grid cols-2">
        <section className="panel">
          <h2>Where the findings came from</h2>
          {Object.keys(per).length === 0 ? <div className="empty">no collector stats in this result</div> : null}
          {Object.entries(per).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
            <div className="dim-bar" key={k}>
              <span className="muted">{k}</span>
              <div className="bar"><i style={{ width: `${(100 * v) / maxPer}%` }} /></div>
              <span className="mono dim">{v}</span>
            </div>
          ))}
          {stats.collectors?.errors?.length ? (
            <div className="small dim" style={{ marginTop: 'var(--s2)' }}>
              {stats.collectors.errors.length} collector error(s) recorded in stats
            </div>
          ) : null}
          <div className="note" style={{ marginTop: 'var(--s4)' }}>
            <b>What these numbers are not.</b> Binary findings (YARA constants, symbols, version strings) prove presence,
            not use, and are capped at medium confidence. Findings marked <i>library capability only</i> come from
            dependency manifests and stay at MONITOR until a call site is seen.
          </div>
        </section>

        <section className="panel">
          <h2>Already exposed · what migrating alone cannot fix</h2>
          {exposed.length === 0 ? (
            <div className="empty">
              Nothing in this tier at Z = {params.z_year}.<br />
              Drag Z earlier to see which data a recording adversary would already have.
            </div>
          ) : (
            <>
              <div className="table-wrap" style={{ maxHeight: 300 }}>
                <table>
                  <thead>
                    <tr><th>asset</th><th>component</th><th className="num">X + Y</th><th className="num">Z</th><th className="num">priority</th></tr>
                  </thead>
                  <tbody>
                    {exposed.slice(0, 10).map((a) => (
                      <tr key={a.bom_ref} onClick={() => onTier('EXPOSED')}>
                        <td><b>{a.name}</b>{a.key_size ? <span className="mono dim">-{a.key_size}</span> : null}</td>
                        <td className="muted">{a.component}</td>
                        <td className="num">{a.risk ? (a.risk.x + a.risk.y).toFixed(1) : '—'}</td>
                        <td className="num dim">{a.risk?.z}</td>
                        <td className="num">{a.risk?.priority}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="small dim" style={{ marginTop: 'var(--s3)' }}>
                For these, re-keying, shortening retention or accepting the loss all belong on the table beside migrating.
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  )
}
