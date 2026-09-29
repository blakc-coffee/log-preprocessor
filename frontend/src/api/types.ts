// Wire types for the control API. They mirror contracts/uef.schema.json (the
// admin payloads the control API passes through) plus the control plane's own
// combined views. Snake case is kept: these are the JSON documents as sent.

export type Hex = string;
export type Timestamp = string; // RFC 3339, UTC, nanoseconds allowed

export interface Endpoint {
  ip?: string;
  port?: number;
  mac?: string;
  hostname?: string;
}

export interface Ocsf {
  class_uid: number;
  category_uid: number;
  activity_id: number;
  type_uid: number;
  time: number;
  severity_id?: number;
  action_id?: number;
  disposition_id?: number;
  src_endpoint?: Endpoint;
  dst_endpoint?: Endpoint;
  connection_info?: { protocol_num?: number; protocol_name?: string };
  traffic?: { bytes_in?: number; bytes_out?: number; packets_in?: number; packets_out?: number };
  metadata?: { version: string; product: { vendor_name: string; name: string } };
  message?: string;
  [key: string]: unknown;
}

export interface EvidenceRef {
  record_id: number;
  kind: 'dhcp' | 'radius' | 'vpn';
}

export interface Entity {
  type: 'user' | 'host' | 'ip' | 'mac';
  id: string;
  role: 'src' | 'dst' | 'observer';
  valid_from: Timestamp | null;
  valid_to: Timestamp | null;
  confidence: number;
  evidence: EvidenceRef[];
}

export interface Coverage {
  applicable: boolean;
  render_back_ok: boolean | null;
  mapped_bytes: number;
  unmapped_bytes: number;
  constant_bytes: number;
  uncovered_bytes: number;
  mapped_fields: number;
  unmapped_fields: number;
}

export interface IdentityFact {
  kind: 'dhcp' | 'radius' | 'vpn';
  action: 'bind' | 'release';
  ip: string;
  mac?: string;
  host?: string;
  user?: string;
  at: Timestamp;
  record_id: number;
  source_id: string;
}

export interface NormalizedEvent {
  event_id: string;
  record_id: number;
  segment: number;
  raw_sha256: Hex;
  source_id: string;
  vendor: string;
  product: string;
  parser_id: string;
  parser_version: string;
  template_id: string;
  schema_version: string;
  received_at: Timestamp;
  event_time: Timestamp | null;
  time_from_receipt: boolean;
  parse_confidence: number;
  integrity_flags: string[];
  ocsf: Ocsf;
  unmapped: Record<string, unknown>;
  entities: Entity[];
  identity?: IdentityFact;
  coverage: Coverage;
  current: boolean;
}

export interface EventList {
  events: NormalizedEvent[];
  next_cursor: string | null;
  max_seq: number;
}

export interface Origin {
  kind: 'unknown' | 'file' | 'udp' | 'tcp' | 'tls' | 'http';
  addr: string;
  offset: number;
}

export interface RawResponse {
  record_id: number;
  segment: number;
  raw_base64: string;
  raw_sha256: Hex;
  sha_match: boolean;
  origin: Origin;
  terminator: 'none' | 'LF' | 'CRLF' | 'NUL';
  fragment: number;
  received_at: Timestamp;
}

export interface Proof {
  segment: number;
  leaf_index: number;
  tree_size: number;
  leaf_hash: Hex;
  path: Hex[];
  root: Hex;
  prev_chain: Hex;
  chain: Hex;
  algorithm: { leaf: string; node: string; chain: string; proof_verification: string };
}

export interface Lineage {
  event_id: string;
  record_id: number;
  raw_sha256: Hex;
  sealed: boolean;
  proof: Proof | null;
  chain: { head: Hex; sealed_through: number };
  coverage: Coverage;
  render_back: { applicable: boolean; ok: boolean | null };
}

export interface QuarantineRecord {
  record_id: number;
  source_id: string;
  failure_stage: 'detect' | 'extract' | 'normalize' | 'integrity';
  error: string;
  received_at: Timestamp;
  status: 'open' | 'resolved' | 'ignored';
  resolved_by?: string;
}

export interface QuarantineSummary {
  source_id: string;
  open: number;
  resolved: number;
  ignored: number;
  by_stage: Record<string, number>;
}

export interface QuarantineList {
  records: QuarantineRecord[];
  next_cursor: string | null;
  summary: QuarantineSummary[];
}

export interface Sample {
  record_id: number;
  source_id: string;
  raw_base64: string;
  received_at: Timestamp;
  status: 'parsed' | 'quarantined';
  parser_id: string;
}

export interface DriftAlert {
  id: string;
  source_id: string;
  parser_id: string;
  score: number;
  signals: string[];
  quarantine_rate: number;
  first_seen: Timestamp;
  status: 'open' | 'proposed' | 'resolved' | 'dismissed';
}

export interface TypedField {
  field: string;
  ocsf_path: string;
  type: string;
  confidence: number;
  evidence: string;
  alternatives?: string[];
}

export interface FieldStat {
  present: number;
  distinct: number;
  sample: string[];
}

export interface DryRunResult {
  samples: number;
  parsed: number;
  failed: number;
  match_rate: number;
  mean_coverage: number;
  render_back_ok_rate: number | null;
  field_stats: Record<string, FieldStat>;
  failures: { record_id: number; error: string }[];
  warnings: string[];
}

export interface Proposal {
  id: string;
  kind: 'new' | 'patch';
  parser_id: string;
  base_version: string;
  source_id: string;
  yaml: string;
  drift_alert_id?: string;
  cluster_size: number;
  templates: string[];
  sample_record_ids: number[];
  typed_fields: TypedField[];
  dry_run: DryRunResult | null;
  status: 'pending' | 'approved' | 'rejected' | 'stale';
  created_at: Timestamp;
}

export interface ProposalView {
  proposal: Proposal;
  active_yaml: string;
}

export interface Activation {
  parser_id: string;
  version: string;
  replay_job_id: string | null;
}

export interface ReplayJob {
  job_id: string;
  state: 'queued' | 'running' | 'done' | 'failed';
  scope: 'quarantine' | 'source' | 'range';
  processed: number;
  succeeded: number;
  failed: number;
  started_at: Timestamp | null;
  finished_at: Timestamp | null;
  error: string | null;
}

export interface ParserInfo {
  id: string;
  active_version: string;
  versions: string[];
  vendor: string;
  product: string;
  signature: string;
}

export interface RegistryRow {
  id: number;
  proposal_id: string;
  parser_id: string;
  from_version: string;
  to_version: string;
  action: 'approve' | 'reject' | 'rollback';
  yaml_sha256: string;
  approved_by: string;
  comment: string;
  at: Timestamp;
  replay_job_id: string;
  result: 'pending' | 'ok' | 'stale' | 'error';
  error: string;
}

export interface ParserVersions {
  parser: ParserInfo;
  versions: { version: string; active: boolean; history: RegistryRow[] }[];
  history: RegistryRow[];
}

export interface Binding {
  kind: 'dhcp' | 'radius' | 'vpn';
  user: string;
  host: string;
  mac: string;
  valid_from: Timestamp;
  valid_to: Timestamp | null;
  confidence: number;
  evidence: EvidenceRef[];
}

export interface Timeline {
  ip: string;
  bindings: Binding[];
}

export interface SegmentSeal {
  segment: number;
  first_seq: number;
  last_seq: number;
  count: number;
  root: Hex;
  prev: Hex;
  chain: Hex;
  sealed_at: Timestamp;
  recovered: boolean;
}

export interface Segments {
  segments: SegmentSeal[];
  active: { segment: number; first_seq: number; records: number };
}

export interface ChainReport {
  ok: boolean;
  deep: boolean;
  segments: number;
  records: number;
  head: Hex;
  first_bad?: number;
  reason?: string;
}

export interface Telemetry {
  eps_1m: number;
  eps_peak: number;
  events_total: number;
  quarantined_total: number;
  quarantine_open: number;
  vault: {
    records: number;
    segments: number;
    bytes_raw: number;
    bytes_compressed: number;
    ratio: number;
    chain_head: Hex;
    sealed_through: number;
    failed: boolean;
  };
  lossless: { last_verify_ok: boolean; last_verify_at: Timestamp };
  sources: { id: string; eps: number; records: number }[];
  sinks: { name: string; lag: number; errors: number }[];
}

export interface Health {
  status: 'ok';
  admin: 'reachable' | 'unreachable' | 'unhealthy';
}
