// Structured edits to a proposed parser: the review queue's typed-field table
// changes the YAML through these functions instead of asking the reviewer to
// hand-edit it (Frontend PRD 3.5). The `yaml` Document API keeps comments,
// order and flow style, so the diff shows only the line that changed.
import { isMap, isScalar, isSeq, parseDocument, type Document, type YAMLMap, type YAMLSeq } from 'yaml';
import type { TypedField } from '../api/types';

// Match the DSL examples' style: `{from: x, to: y}` without inner padding and
// no line folding, so an edit changes exactly the line it touches.
const STRINGIFY = { flowCollectionPadding: false, lineWidth: 0 } as const;

export interface EditResult {
  yaml: string;
  error?: string;
}

// The DSL type a mapping gets from the typer's value type.
const DSL_TYPE: Record<string, string> = {
  ipv4: 'ip',
  ipv6: 'ip',
  ip: 'ip',
  port: 'port',
  mac: 'mac',
  bytes: 'uint',
  packets: 'uint',
  int: 'int',
  username: 'string',
  hostname: 'string',
  string: 'string',
  protocol: 'string',
  url: 'string',
  email: 'string',
  uuid: 'string',
  hash: 'string',
};

/** OCSF paths the reviewer can pick. Paths ending in _id need an enum and are edited in the YAML. */
export const OCSF_PATHS = [
  'src_endpoint.ip',
  'src_endpoint.port',
  'src_endpoint.mac',
  'src_endpoint.hostname',
  'dst_endpoint.ip',
  'dst_endpoint.port',
  'dst_endpoint.hostname',
  'connection_info.protocol_name',
  'connection_info.protocol_num',
  'traffic.bytes_in',
  'traffic.bytes_out',
  'traffic.packets_in',
  'traffic.packets_out',
  'actor.user.name',
  'time',
  'message',
];

function extractors(doc: Document): YAMLMap[] {
  const ex = doc.get('extractors');
  return isSeq(ex) ? (ex.items.filter(isMap) as YAMLMap[]) : [];
}

/** The capture name a typed field refers to: a csv column's name, else the field itself. */
function captureName(ex: YAMLMap, field: string): { name: string; columns?: YAMLSeq; index?: number } {
  const m = /^col_(\d+)$/.exec(field);
  const cols = ex.get('columns');
  if (m && isSeq(cols)) {
    const index = Number(m[1]);
    const item = cols.items[index];
    const name = isScalar(item) ? String(item.value) : '_';
    return { name, columns: cols as YAMLSeq, index };
  }
  return { name: field };
}

function fromMatches(node: unknown, name: string): boolean {
  if (isScalar(node)) return String(node.value) === name;
  if (isSeq(node)) return node.items.some((i) => isScalar(i) && String(i.value) === name);
  return false;
}

/**
 * Points typed field `f` at `path` ("" unmaps it). Returns the new YAML, or
 * an error the UI shows next to the row when the change needs a hand edit.
 */
export function setFieldPath(yaml: string, f: TypedField, path: string): EditResult {
  const doc = parseDocument(yaml);
  if (doc.errors.length) return { yaml, error: `The YAML does not parse: ${doc.errors[0]!.message}` };
  if (path.endsWith('_id')) return { yaml, error: `${path} needs an enum table; edit it in the YAML.` };
  for (const ex of extractors(doc)) {
    const map = ex.get('map');
    if (!isSeq(map)) continue;
    const cap = captureName(ex, f.field);
    const idx = map.items.findIndex(
      (e) =>
        isMap(e) && fromMatches(e.get('from', true), cap.name) && (f.ocsf_path === '' || e.get('to') === f.ocsf_path),
    );
    if (idx >= 0) {
      if (path === '') map.items.splice(idx, 1);
      else (map.items[idx] as YAMLMap).set('to', path);
      return { yaml: doc.toString(STRINGIFY) };
    }
    if (path === '') continue;
    // Abstained field: give the column a name if it has none, then map it.
    let name = cap.name;
    if (cap.columns && cap.index !== undefined) {
      if (cap.index >= cap.columns.items.length) continue;
      if (name === '_') {
        name = f.field;
        cap.columns.set(cap.index, doc.createNode(name));
      }
    }
    const entry = doc.createNode({ from: name, to: path, type: DSL_TYPE[f.type] ?? 'string' }) as YAMLMap;
    entry.flow = true;
    map.items.push(entry);
    return { yaml: doc.toString(STRINGIFY) };
  }
  return { yaml, error: `No extractor in the YAML reads ${f.field}.` };
}

/** Reads `version`, `ocsf_defaults.class_uid` and the first match signature, for the registry panel. */
export function summarizeParser(yaml: string): {
  version?: string;
  classUid?: number;
  signature?: string;
  kinds: string[];
  mappings: { from: string; to: string }[];
} {
  const doc = parseDocument(yaml);
  const out: ReturnType<typeof summarizeParser> = { kinds: [], mappings: [] };
  if (doc.errors.length) return out;
  const v = doc.get('version');
  if (v !== undefined) out.version = String(v);
  const cls = doc.getIn(['ocsf_defaults', 'class_uid']);
  if (typeof cls === 'number') out.classUid = cls;
  const sig = doc.getIn(['match', 'signature']);
  if (typeof sig === 'string') out.signature = sig;
  for (const ex of extractors(doc)) {
    const k = ex.get('kind');
    if (typeof k === 'string' && !out.kinds.includes(k)) out.kinds.push(k);
    const map = ex.get('map');
    if (!isSeq(map)) continue;
    for (const e of map.items) {
      if (!isMap(e)) continue;
      const to = e.get('to');
      const from: unknown = e.get('from', true);
      const src = isScalar(from)
        ? String(from.value)
        : isSeq(from)
          ? from.items.map((i) => (isScalar(i) ? String(i.value) : '?')).join('+')
          : 'const';
      if (typeof to === 'string') out.mappings.push({ from: e.has('const') ? `= ${String(e.get('const'))}` : src, to });
    }
  }
  return out;
}

export const OCSF_CLASS: Record<number, string> = {
  4001: 'network_activity',
  4004: 'dhcp_activity',
  3002: 'authentication',
};
