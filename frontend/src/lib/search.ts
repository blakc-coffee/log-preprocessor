// The explorer's free-form search box. It recognises IPs, prefixed terms and
// vendor names and turns them into admin filter parameters. Anything it
// cannot map is reported back rather than silently ignored.

export interface SearchResult {
  params: Record<string, string>;
  terms: { key: string; value: string }[];
  unsupported: string[];
}

const KNOWN_VENDORS = new Set(['cisco', 'fortinet', 'oisf', 'palo_alto', 'isc', 'freeradius']);
const VENDOR_ALIASES: Record<string, string> = {
  asa: 'cisco',
  suricata: 'oisf',
  fortigate: 'fortinet',
  paloalto: 'palo_alto',
  'palo-alto': 'palo_alto',
  dhcp: 'isc',
  radius: 'freeradius',
};
const PREFIXES: Record<string, string> = {
  ip: 'ip',
  src: 'src_ip',
  dst: 'dst_ip',
  user: 'user',
  host: 'host',
  vendor: 'vendor',
  source: 'source_id',
  flag: 'flag',
};

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

export function isIP(s: string): boolean {
  return IPV4.test(s) || (s.includes(':') && s.length >= 2 && IPV6.test(s));
}

export function parseSearch(q: string): SearchResult {
  const res: SearchResult = { params: {}, terms: [], unsupported: [] };
  const set = (key: string, value: string) => {
    res.params[key] = value;
    res.terms.push({ key, value });
  };
  for (const tok of q.trim().split(/\s+/).filter(Boolean)) {
    const colon = tok.indexOf(':');
    const prefix = colon > 0 ? tok.slice(0, colon).toLowerCase() : '';
    if (prefix && PREFIXES[prefix] && !isIP(tok)) {
      const value = tok.slice(colon + 1);
      if (value)
        set(
          PREFIXES[prefix]!,
          prefix === 'vendor' ? (VENDOR_ALIASES[value.toLowerCase()] ?? value.toLowerCase()) : value,
        );
      continue;
    }
    if (isIP(tok)) {
      set('ip', tok);
      continue;
    }
    if (/^[0-9a-f]{64}$/i.test(tok)) {
      res.unsupported.push('raw hash search needs an admin API filter that does not exist yet');
      continue;
    }
    const lower = tok.toLowerCase();
    if (KNOWN_VENDORS.has(lower) || VENDOR_ALIASES[lower]) {
      set('vendor', VENDOR_ALIASES[lower] ?? lower);
      continue;
    }
    set('user', tok);
  }
  return res;
}
