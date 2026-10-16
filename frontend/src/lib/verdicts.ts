import type {
  EmailSecurity,
  HeaderCheck,
  MxRecord,
  NetworkExtended,
  ScanResponse,
  SecurityHeaders,
  Subdomain,
  TakeoverEntry,
} from "../api/types";
import { moduleState } from "./moduleState";

// Verdict partagé par les cartes, le résultat et le PDF : `label` est une clé
// i18n (avec `params`), `detail` un texte du serveur affiché tel quel.
export type Level = "ok" | "warning" | "critical" | "neutral" | "na";

export interface Verdict {
  level: Level;
  label: string;
  params?: Record<string, unknown>;
  detail?: string | null;
}

// HTTPS absent et certificat invalide sont des constats (0/20 au score) ; un
// hôte injoignable est « non mesuré », pas « absent ».
export function tlsVerdict(scan: ScanResponse): Verdict {
  const tls = scan.tls_certificate ?? {};
  if (typeof tls.error === "string" && /certificate verify failed/i.test(tls.error)) {
    return { level: "critical", label: "verdict.tls.invalid", detail: tls.error };
  }
  const state = moduleState(scan, "tls_certificate", tls);
  if (state.status !== "ok") return { level: "na", label: `moduleStatus.${state.status}`, detail: state.error };
  if (tls.error) return { level: "na", label: "moduleStatus.failed", detail: tls.error };
  if (tls.https === false) return { level: "critical", label: "verdict.tls.noHttps", detail: tls.verify_error ?? null };
  if (tls.valid === false) return { level: "critical", label: "verdict.tls.invalid", detail: tls.verify_error ?? null };
  const days = Number(tls.days_remaining);
  if (tls.days_remaining != null && Number.isFinite(days)) {
    return { level: days > 30 ? "ok" : days > 7 ? "warning" : "critical", label: "verdict.tls.validDays", params: { days } };
  }
  if (tls.valid === true || tls.subject) return { level: "ok", label: "verdict.tls.valid" };
  return { level: "na", label: "verdict.tls.noInfo" };
}

// Nom lu dans un scan : texte non vide, sinon null (jamais un faux nom).
export function cleanName(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

// Sous-domaines testés au plus par le module takeover
// (TAKEOVER_MAX_SUBDOMAINS, domainrecon/scanner/takeover.py).
export const TAKEOVER_MAX_SUBDOMAINS = 15;

// Entrée d'un scan antérieur sans `confirmed` : même règle que le score.
export function takeoverConfirmed(entry: TakeoverEntry): boolean {
  if (typeof entry.confirmed === "boolean") return entry.confirmed;
  return (entry.risk ?? "high") === "high" && entry.fingerprint_matched !== false;
}

export function takeoverTested(scan: ScanResponse): number | null {
  if (scan.module_status?.subdomain_takeover?.status !== "ok") return null;
  const names = new Set(
    (scan.subdomains ?? []).map((s) => String(s?.subdomain ?? "").toLowerCase()).filter(Boolean),
  );
  return Math.min(names.size, TAKEOVER_MAX_SUBDOMAINS);
}

export function takeoverVerdict(scan: ScanResponse): Verdict {
  const entries = (scan.subdomain_takeover ?? []).filter((entry) => entry && typeof entry === "object");
  if (entries.length) {
    const confirmed = entries.filter(takeoverConfirmed).length;
    const toCheck = entries.length - confirmed;
    // Jamais de compteur à zéro dans le résumé (« 0 confirmé(s) »).
    if (!toCheck) return { level: "critical", label: "verdict.takeover.confirmedOnly", params: { count: confirmed } };
    if (!confirmed) return { level: "warning", label: "verdict.takeover.toCheckOnly", params: { count: toCheck } };
    return { level: "critical", label: "verdict.takeover.found", params: { confirmed, toCheck } };
  }
  const state = moduleState(scan, "subdomain_takeover");
  if (state.status === "skipped") return { level: "neutral", label: "moduleStatus.skipped", detail: state.error };
  if (state.status !== "ok") return { level: "warning", label: "verdict.takeover.notChecked", detail: state.error };
  const tested = takeoverTested(scan);
  return tested
    ? { level: "ok", label: "verdict.takeover.noneTested", params: { count: tested } }
    : { level: "ok", label: "verdict.takeover.none" };
}

// Liste enregistrée plafonnée ; module_status.subdomains.total_found compte
// les noms trouvés.
export function subdomainCount(scan: ScanResponse): { shown: number; total: number } {
  const shown = (scan.subdomains ?? []).length;
  const found = Number(scan.module_status?.subdomains?.total_found);
  return Number.isInteger(found) && found > shown ? { shown, total: found } : { shown, total: shown };
}

export type ResolutionKind = "wildcard" | "resolved" | "untested" | "unresolved";

// Seuls les premiers noms sont résolus ; une résolution par joker DNS ne
// prouve pas que le nom existe.
export function subdomainResolution(sub: Subdomain): { kind: ResolutionKind; ip: string | null } {
  if (sub?.ip && sub.wildcard === true) return { kind: "wildcard", ip: sub.ip };
  if (sub?.ip) return { kind: "resolved", ip: sub.ip };
  if (sub?.resolution === "not_tested") return { kind: "untested", ip: null };
  return { kind: "unresolved", ip: null };
}

// MX nul (RFC 7505, « 0 . ») ; scan antérieur : valeur « . » enregistrée vide.
export function isNullMx(value: MxRecord | null | undefined): boolean {
  return Boolean(value && typeof value === "object" && (value.null_mx === true || value.value === "." || value.value === ""));
}

// Texte d'un enregistrement DNS (MX et SOA sont des objets).
export function dnsValueText(value: unknown, nullMxLabel: string): string {
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (isNullMx(record as MxRecord)) return `${record.priority ?? 0} . ${nullMxLabel}`.trim();
    if ("priority" in record || "value" in record) return `${record.priority ?? ""} ${record.value ?? ""}`.trim();
    if ("mname" in record) return `${record.mname ?? ""} ${record.rname ?? ""}`.trim();
    return JSON.stringify(record);
  }
  return String(value);
}

// Domaine réellement interrogé par le WHOIS, s'il diffère de la cible.
export function whoisOtherDomain(scan: ScanResponse): string {
  const queried = scan.whois_data?.queried_domain;
  return typeof queried === "string" && queried && queried.toLowerCase() !== String(scan.domain ?? "").toLowerCase()
    ? queried
    : "";
}

// Statuts EPP sans URL ni doublon (sans tenir compte de la casse).
export function whoisStatuses(list: string[] | null | undefined): string[] {
  const seen = new Set<string>();
  return (Array.isArray(list) ? list : [])
    .map((status) => String(status ?? "").replace(/\(?https?:\/\/\S+\)?/g, "").trim())
    .filter((status) => {
      const key = status.toLowerCase().replace(/\s+/g, "");
      if (!status || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

// IP partagée par de nombreux sites (anycast, CDN) : voisins et géolocalisation
// n'y décrivent pas la cible.
export function sharedCdnIp(scan: ScanResponse): boolean {
  return (
    scan.network_extended?.asn_info?.anycast === true || scan.geo_data?.anycast === true || scan.waf?.cdn_detected === true
  );
}

// Domaine qui déclare n'envoyer ni recevoir de courrier (même règle que le serveur).
export function emailWithoutMail(es: EmailSecurity | null | undefined): boolean {
  return es?.null_mx === true && es.spf?.grade === "A" && es.dmarc?.grade === "A";
}

// En-têtes notés (SECURITY_HEADERS de domainrecon/scanner/headers.py).
export const SECURITY_HEADER_NAMES: readonly string[] = [
  "Strict-Transport-Security",
  "X-Frame-Options",
  "X-Content-Type-Options",
  "Content-Security-Policy",
  "Referrer-Policy",
  "Permissions-Policy",
];

const HEADER_STATUSES = ["ok", "weak", "invalid", "missing", "info"] as const;

export interface HeaderRow {
  name: string;
  value: string | null;
  status: (typeof HEADER_STATUSES)[number];
  detail: string | null;
  legacy: boolean;
}

// Verdicts du serveur (checks) ; scan antérieur : simple présence des en-têtes
// notés. Un statut inconnu vaut « absent ».
export function headerChecks(sec: SecurityHeaders | null | undefined): HeaderRow[] {
  const checks = sec?.checks && typeof sec.checks === "object" ? Object.entries(sec.checks) : [];
  if (checks.length) {
    return checks
      .filter((entry): entry is [string, HeaderCheck] => Boolean(entry[1]) && typeof entry[1] === "object")
      .map(([name, check]) => ({
        name,
        value: check.value ?? null,
        status: (HEADER_STATUSES as readonly string[]).includes(check.status)
          ? (check.status as HeaderRow["status"])
          : "missing",
        detail: check.detail ?? null,
        legacy: false,
      }));
  }
  const found = sec?.headers_found ?? {};
  return SECURITY_HEADER_NAMES.map((name) => ({
    name,
    value: Object.hasOwn(found, name) ? found[name] : null,
    status: Object.hasOwn(found, name) ? "ok" : "missing",
    detail: null,
    legacy: true,
  }));
}

// Voisins reverse-IP : liste plafonnée par le serveur (neighbors_total).
export function neighborsCount(net: NetworkExtended | null | undefined): { shown: number; total: number } {
  const shown = (net?.reverse_ip_neighbors ?? []).length;
  const total = Number(net?.neighbors_total);
  return Number.isInteger(total) && total > shown ? { shown, total } : { shown, total: shown };
}
