import { exportUrl, type ExportKind } from '../api'

const KINDS: { kind: ExportKind; label: string; title: string }[] = [
  { kind: 'cbom', label: 'CBOM 1.7', title: 'CycloneDX 1.7 CBOM JSON (ML-DSA-65 signed alongside)' },
  { kind: 'vex', label: 'VEX', title: 'CycloneDX VEX: affected / not_affected / resolved / in_triage per finding (CERT-In 8.4.1.6)' },
  { kind: 'sarif', label: 'SARIF', title: 'SARIF 2.1.0 for GitHub code scanning' },
  { kind: 'csv', label: 'CSV', title: 'RFC 4180 CSV, formula-injection hardened' },
  { kind: 'report.html', label: 'HTML', title: 'Self-contained technical report' },
  { kind: 'report.pdf', label: 'PDF', title: 'Executive report' },
]

export default function Export({ id, disabled }: { id: string; disabled: boolean }) {
  return (
    <div className="exports">
      {KINDS.map((k) => (
        <a
          key={k.kind}
          href={disabled ? undefined : exportUrl(id, k.kind)}
          title={disabled ? 'exports need a running ecdat server' : k.title}
          style={disabled ? { opacity: 0.4, pointerEvents: 'none' } : undefined}
          target="_blank"
          rel="noreferrer"
        >
          {k.label}
        </a>
      ))}
    </div>
  )
}
