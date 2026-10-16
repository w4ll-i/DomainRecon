// Glossaire : une clé par terme, textes dans l'espace « glossary.<clé>.name » et
// « glossary.<clé>.def » des catalogues FR et EN. Sert aux infobulles (components/Term.tsx)
// et à la page Aide.
export const GLOSSARY_KEYS = [
  "spf",
  "dkim",
  "dmarc",
  "bimi",
  "mta_sts",
  "tls_rpt",
  "dane",
  "dnssec",
  "caa",
  "hsts",
  "csp",
  "cors",
  "x_frame_options",
  "referrer_policy",
  "permissions_policy",
  "httponly",
  "samesite",
  "asn",
  "bgp",
  "ct",
  "ocsp",
  "tls",
  "certificate",
  "ca",
  "san",
  "cipher",
  "pfs",
  "dns",
  "a_record",
  "aaaa_record",
  "mx",
  "ns",
  "txt",
  "cname",
  "soa",
  "ptr",
  "ttl",
  "zone_transfer",
  "wildcard_dns",
  "subdomain",
  "takeover",
  "waf",
  "cdn",
  "whois",
  "rdap",
  "open_port",
  "banner",
  "typosquatting",
  "dnsbl",
  "osint",
  "passive",
  "active",
  "proxy",
  "sarif",
] as const;

export type GlossaryKey = (typeof GLOSSARY_KEYS)[number];

// Sigles reconnus dans un texte courant (constats, aide du catalogue) → terme du glossaire.
export const ACRONYMS: Readonly<Record<string, GlossaryKey>> = {
  SPF: "spf",
  DKIM: "dkim",
  DMARC: "dmarc",
  BIMI: "bimi",
  "MTA-STS": "mta_sts",
  "TLS-RPT": "tls_rpt",
  DANE: "dane",
  DNSSEC: "dnssec",
  CAA: "caa",
  HSTS: "hsts",
  CSP: "csp",
  CORS: "cors",
  ASN: "asn",
  BGP: "bgp",
  OCSP: "ocsp",
  TLS: "tls",
  CNAME: "cname",
  TTL: "ttl",
  WAF: "waf",
  CDN: "cdn",
  WHOIS: "whois",
  RDAP: "rdap",
  DNSBL: "dnsbl",
  OSINT: "osint",
  SARIF: "sarif",
  CT: "ct",
};

const ESCAPED = Object.keys(ACRONYMS)
  .sort((a, b) => b.length - a.length)
  .map((name) => name.replace(/[.*+?^${}()|[\]\\-]/g, "\\$&"));

// Un sigle entier, sans lettre ni chiffre collé de part et d'autre.
export const ACRONYM_PATTERN = new RegExp(`(?<![A-Za-z0-9])(${ESCAPED.join("|")})(?![A-Za-z0-9])`, "g");

export type GlossarySegment = { text: string; term?: GlossaryKey };

// Découpe un texte en segments : le texte courant et les sigles du glossaire.
export function splitGlossary(text: string): GlossarySegment[] {
  const segments: GlossarySegment[] = [];
  let last = 0;
  for (const match of text.matchAll(ACRONYM_PATTERN)) {
    const index = match.index ?? 0;
    if (index > last) segments.push({ text: text.slice(last, index) });
    segments.push({ text: match[0], term: ACRONYMS[match[0]] });
    last = index + match[0].length;
  }
  if (last < text.length) segments.push({ text: text.slice(last) });
  return segments;
}
