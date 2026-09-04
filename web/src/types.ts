// Mirrors ecdat/model.py (ScanResult.to_dict()) plus the dicts produced by risk/mosca.py, plan/optimizer.py,
// normalize/certin.py and risk/frameworks.py. Keep field names identical to the Python side.

export type Tier = 'EXPOSED' | 'ACT_NOW' | 'MONITOR' | 'SAFE'
export type AssetType = 'algorithm' | 'certificate' | 'protocol' | 'related-crypto-material' | 'library'
export type Confidence = 'high' | 'medium' | 'low'

export interface Evidence {
  collector: string
  location: string
  line: number | null
  snippet: string | null
  confidence: Confidence
  context: Record<string, unknown>
}

export interface Agility {
  dimensions: Record<string, number>
  total: number
  y_years: number
  reasons: string[]
}

export interface Overlay {
  framework: string
  rule: string
  status: 'violation' | 'warning' | 'ok'
  deadline_year: number | null
  text: string
  kind?: string
}

export interface Risk {
  quantum_class: string
  reason: string
  hndl_applicable: boolean
  x: number
  y: number
  z: number
  mosca_gap: number
  tier: Tier
  priority: number
  deadline_year: number | null
  overlays: Overlay[]
  reasons: string[]
}

export interface Patch {
  title: string
  file: string
  line?: number | null
  unified_diff: string
  note?: string
}

export interface Recommendation {
  target: string | null
  alternative: string | null
  cnsa_target: string | null
  fips: string[]
  deltas: Record<string, unknown>
  runtime_note: string
  effort_weeks: number
  hybrid: boolean
  rationale: string
  patches: Patch[]
}

export interface Exposure {
  zone?: string
  transit?: boolean
  at_rest?: boolean
  signing_only?: boolean
  confidentiality?: boolean
  reason?: string
}

export interface CertIn {
  table?: string | null
  present?: string[]
  missing?: string[]
  pct?: number | null
}

export interface Asset {
  bom_ref: string
  asset_type: AssetType
  name: string
  family: string | null
  primitive: string | null
  key_size: number | null
  mode: string | null
  padding: string | null
  oid: string | null
  parameter_set: string | null
  curve: string | null
  crypto_functions: string[]
  classical_security_level: number | null
  nist_quantum_security_level: number | null
  component: string
  provided_by: string | null
  confidence: Confidence
  evidence: Evidence[]
  props: Record<string, unknown>
  context: Record<string, unknown>
  exposure: Exposure
  lifetime_years: number | null
  data_class: string | null
  criticality: string | null
  criticality_multiplier: number
  agility: Agility | null
  risk: Risk | null
  recommendation: Recommendation | null
  vex: string
  certin: CertIn
}

export interface Component {
  bom_ref: string
  name: string
  type: string
  version: string | null
  zone: string
  data_class: string | null
  criticality: string | null
  path: string | null
  props: Record<string, unknown>
}

export interface Params {
  z_year: number
  y_default: number
  engineers: number
  months: number
  profile: string
  now_year: number
  passwords?: string[]
  use_external_tools?: boolean
}

export interface PlanItem {
  bom_ref: string
  name: string
  asset_type: string
  component: string
  tier: Tier
  priority: number
  effort_weeks: number
  risk_per_week?: number
  target: string | null
  cumulative_weeks?: number
  cumulative_risk_pct?: number
  location?: string | null
}

export interface Plan {
  engineers: number
  months: number
  capacity_weeks: number
  used_weeks: number
  items: PlanItem[]
  uncovered: PlanItem[]
  covered_pct: number
  total_risk: number
  candidates: number
  exposed_remaining: number
}

export interface CertInSummary {
  by_type: Record<string, number>
  counts: Record<string, number>
  top_missing: [string, number][]
  overall_pct: number | null
  source: string
}

export interface Stats {
  assets?: number
  tiers?: Record<Tier, number>
  quantum_classes?: Record<string, number>
  hndl_applicable?: number
  z_year?: number
  certin?: CertInSummary
  collectors?: {
    per_collector?: Record<string, number>
    per_target?: Record<string, number>
    errors?: { target: string; collector: string; error: string }[]
    total_findings?: number
  }
}

export interface ScanResult {
  id: string
  name: string
  timestamp: string
  targets: Record<string, unknown>[]
  components: Component[]
  assets: Asset[]
  params: Params
  stats: Stats
  plan: Partial<Plan>
  tool_versions: Record<string, string | null>
}

export interface ResultSummary {
  id: string
  name: string
  timestamp: string
  counts?: Record<string, number>
}

export const TIERS: Tier[] = ['EXPOSED', 'ACT_NOW', 'MONITOR', 'SAFE']
export const TIER_LABEL: Record<Tier, string> = {
  EXPOSED: 'ALREADY EXPOSED',
  ACT_NOW: 'ACT NOW',
  MONITOR: 'MONITOR',
  SAFE: 'SAFE',
}
export const TIER_COLOR: Record<Tier, string> = {
  EXPOSED: '#ff5d52',
  ACT_NOW: '#f2b134',
  MONITOR: '#6fa9ff',
  SAFE: '#4fd18b',
}
export const Z_PRESETS: { key: string; year: number; label: string }[] = [
  { key: 'aggressive', year: 2032, label: 'aggressive 2032' },
  { key: 'nist', year: 2035, label: 'NIST disallow 2035' },
  { key: 'gri', year: 2041, label: 'GRI median 2041' },
]
export const DST_MILESTONES: Record<string, { M1: number; M2: number; M3: number }> = {
  cii: { M1: 2027, M2: 2028, M3: 2029 },
  enterprise: { M1: 2028, M2: 2030, M3: 2033 },
}
