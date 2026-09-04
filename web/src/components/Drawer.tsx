import type { Asset } from '../types'
import { TIER_LABEL } from '../types'

const DIM_LABEL: Record<string, string> = {
  algorithm_coupling: 'algorithm coupling',
  provider_coupling: 'provider coupling',
  parameter_coupling: 'parameter coupling',
  decoupling: 'decoupling mechanism',
  spread: 'spread (call sites)',
  ownership: 'ownership',
  runtime_pqc: 'runtime PQC support',
}

function fmt(v: unknown): string {
  if (v === null || v === undefined) return '-'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

export default function Drawer({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const r = asset.risk
  const ag = asset.agility
  const rec = asset.recommendation
  const ctx = asset.context || {}
  const ex = asset.exposure || {}
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`asset ${asset.name}`}>
        <button className="close" onClick={onClose}>close</button>
        <h2>
          {asset.name}
          {asset.key_size ? <span className="mono">-{asset.key_size}</span> : null}
          <small>{asset.asset_type} · {asset.component}</small>
        </h2>
        <div className="row" style={{ marginTop: 8, flexWrap: 'wrap' }}>
          {r ? <span className={`badge tier-${r.tier}`}>{TIER_LABEL[r.tier]}</span> : null}
          <span className={`badge conf-${asset.confidence}`}>confidence {asset.confidence}</span>
          {ctx.corroborated ? <span className="badge amber">corroborated</span> : null}
          {ctx.best_effort ? <span className="badge">best-effort (binary)</span> : null}
          {ctx.from_library_only ? <span className="badge">library capability only</span> : null}
          {ctx.usage ? <span className="badge">usage: {String(ctx.usage)}</span> : null}
          <span className="badge">vex: {asset.vex}</span>
        </div>

        <section>
          <h3>Cryptographic properties</h3>
          <dl className="kv">
            <dt>family</dt><dd>{fmt(asset.family)}</dd>
            <dt>primitive</dt><dd>{fmt(asset.primitive)}</dd>
            <dt>key size / curve</dt><dd>{fmt(asset.key_size)} {asset.curve ? `/ ${asset.curve}` : ''}</dd>
            <dt>mode / padding</dt><dd>{fmt(asset.mode)} / {fmt(asset.padding)}</dd>
            <dt>OID</dt><dd>{fmt(asset.oid)}</dd>
            <dt>functions</dt><dd>{asset.crypto_functions?.join(', ') || '-'}</dd>
            <dt>classical security</dt><dd>{fmt(asset.classical_security_level)} bits</dd>
            <dt>NIST PQC level</dt><dd>{fmt(asset.nist_quantum_security_level)}</dd>
            <dt>provided by</dt><dd>{fmt(asset.provided_by)}</dd>
            <dt>CERT-In Table 9</dt>
            <dd>
              {asset.certin?.pct != null ? `${asset.certin.pct}% complete` : '-'}
              {asset.certin?.missing?.length ? ` (missing: ${asset.certin.missing.join(', ')})` : ''}
            </dd>
          </dl>
          {asset.asset_type === 'certificate' ? (
            <dl className="kv" style={{ marginTop: 8 }}>
              <dt>subject</dt><dd>{fmt(asset.props.subject)}</dd>
              <dt>issuer</dt><dd>{fmt(asset.props.issuer)}</dd>
              <dt>valid</dt><dd>{fmt(asset.props.not_before)} to {fmt(asset.props.not_after)} {asset.props.expired ? '(EXPIRED)' : ''}</dd>
              <dt>signature</dt><dd>{fmt(asset.props.signature_algorithm)} / {fmt(asset.props.signature_hash)}</dd>
              <dt>public key</dt><dd>{fmt(asset.props.public_key_algorithm)}-{fmt(asset.props.key_size)}</dd>
            </dl>
          ) : null}
          {asset.asset_type === 'protocol' ? (
            <dl className="kv" style={{ marginTop: 8 }}>
              <dt>versions</dt><dd>{fmt((asset.props.versions as string[] | undefined)?.join(', '))}</dd>
              <dt>cipher suites</dt><dd>{fmt((asset.props.cipher_suites as string[] | undefined)?.join(', '))}</dd>
              <dt>key exchange group</dt><dd>{fmt(asset.props.kex_group)} {asset.props.pq_kex ? '(post-quantum)' : ''}</dd>
            </dl>
          ) : null}
        </section>

        <section>
          <h3>Evidence ({asset.evidence.length})</h3>
          <ul className="evidence">
            {asset.evidence.slice(0, 25).map((e, i) => (
              <li key={i}>
                <span className="tag">{e.collector}</span>
                <span className="loc">{e.location}{e.line ? `:${e.line}` : ''}</span>
                {e.snippet ? <div className="snip">{e.snippet}</div> : null}
              </li>
            ))}
          </ul>
        </section>

        <section>
          <h3>Exposure and data</h3>
          <dl className="kv">
            <dt>zone</dt><dd>{fmt(ex.zone)}</dd>
            <dt>in transit / at rest</dt><dd>{String(!!ex.transit)} / {String(!!ex.at_rest)}</dd>
            <dt>signing only</dt><dd>{String(!!ex.signing_only)}</dd>
            <dt>data class</dt><dd>{fmt(asset.data_class)} ({fmt(asset.lifetime_years)} years to stay secret)</dd>
            <dt>criticality</dt><dd>{fmt(asset.criticality)} (x{asset.criticality_multiplier})</dd>
            {ex.reason ? (<><dt>reason</dt><dd>{ex.reason}</dd></>) : null}
          </dl>
        </section>

        {ag ? (
          <section>
            <h3>Crypto-agility {ag.total}/100 · migration ~{ag.y_years} y</h3>
            {Object.entries(ag.dimensions).map(([k, v]) => (
              <div className="dim-bar" key={k}>
                <span className="muted">{DIM_LABEL[k] || k}</span>
                <div className="bar"><i style={{ width: `${Math.round((1 - v) * 100)}%` }} /></div>
                <span className="mono dim">{Math.round((1 - v) * 100)}</span>
              </div>
            ))}
            <ul className="small muted">{ag.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>
          </section>
        ) : null}

        {r ? (
          <section>
            <h3>Quantum risk</h3>
            <dl className="kv">
              <dt>class</dt><dd>{r.quantum_class} {r.reason ? `- ${r.reason}` : ''}</dd>
              <dt>HNDL applies</dt><dd>{String(r.hndl_applicable)}</dd>
              <dt>Mosca X + Y vs Z</dt><dd>{r.x} + {r.y} = {(r.x + r.y).toFixed(1)} vs {r.z} (gap {r.mosca_gap > 0 ? '+' : ''}{r.mosca_gap} y)</dd>
              <dt>priority</dt><dd>{r.priority}</dd>
              <dt>earliest deadline</dt><dd>{fmt(r.deadline_year)}</dd>
            </dl>
            <ul className="small muted">{r.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul>
            {r.overlays?.length ? (
              <div style={{ marginTop: 8 }}>
                {r.overlays.map((o, i) => (
                  <div className="overlay" key={i}>
                    <span className={`mono st-${o.status}`}>{o.framework}</span>
                    <span><b className="small">{o.rule}</b>{o.deadline_year ? <span className="dim"> · {o.deadline_year}</span> : null}<div className="small muted">{o.text}</div></span>
                  </div>
                ))}
              </div>
            ) : null}
          </section>
        ) : null}

        {rec ? (
          <section>
            <h3>Recommendation</h3>
            <dl className="kv">
              <dt>target</dt><dd>{fmt(rec.target)} {rec.hybrid ? '(hybrid)' : ''}</dd>
              <dt>alternative</dt><dd>{fmt(rec.alternative)}</dd>
              <dt>CNSA 2.0 target</dt><dd>{fmt(rec.cnsa_target)}</dd>
              <dt>standards</dt><dd>{rec.fips?.join(', ') || '-'}</dd>
              <dt>effort</dt><dd>{rec.effort_weeks} engineer-weeks</dd>
              <dt>runtime</dt><dd>{fmt(rec.runtime_note)}</dd>
              <dt>rationale</dt><dd>{fmt(rec.rationale)}</dd>
            </dl>
            {rec.deltas && Object.keys(rec.deltas).length ? (
              <>
                <h3 style={{ marginTop: 10 }}>Size and latency deltas</h3>
                <dl className="kv">
                  {Object.entries(rec.deltas).map(([k, v]) => (<><dt key={`k${k}`}>{k}</dt><dd key={`v${k}`}>{fmt(v)}</dd></>))}
                </dl>
              </>
            ) : null}
            {rec.patches?.length ? (
              <>
                <h3 style={{ marginTop: 10 }}>Suggested patches (never auto-applied)</h3>
                {rec.patches.map((p, i) => (
                  <div key={i}>
                    <div className="small"><b>{p.title}</b> <span className="dim mono">{p.file}{p.line ? `:${p.line}` : ''}</span></div>
                    {p.note ? <div className="small muted">{p.note}</div> : null}
                    <pre>{p.unified_diff}</pre>
                  </div>
                ))}
              </>
            ) : null}
          </section>
        ) : null}
      </aside>
    </>
  )
}
