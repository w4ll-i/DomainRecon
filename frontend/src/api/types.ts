// Formes JSON de l'API (phase 1). Les textes destinés à l'utilisateur
// (erreurs, issues, recommandations, notes, détails du score, résumés des
// familles, constats) arrivent DÉJÀ RENDUS dans la langue demandée (?lang=) :
// ce sont des chaînes. Les champs optionnels tiennent compte des anciens scans.
export type { Lang } from "../i18n";

// Les 18 modules historiques, qui ont chacun un champ propre dans le scan et un
// composant dédié.
export type LegacyModuleName =
  | "dns_records"
  | "subdomains"
  | "security_headers"
  | "tls_certificate"
  | "technologies"
  | "geo_data"
  | "whois_data"
  | "open_ports"
  | "email_security"
  | "waf"
  | "redirect_chain"
  | "web_files"
  | "cookie_security"
  | "cors"
  | "reverse_dns"
  | "network_extended"
  | "screenshot"
  | "subdomain_takeover";

// Nom de n'importe quel module du registre : les modules ajoutés depuis les 18
// historiques sont connus par le catalogue (GET /api/modules), pas par ce fichier.
export type ModuleName = string;

export type ModuleRunStatus = "ok" | "failed" | "timeout" | "skipped";

export interface ModuleStatusEntry {
  status: ModuleRunStatus;
  error: string | null;
  total_found?: number;
  source?: string;
  partial?: boolean;
}

// Résultat générique d'un module du registre (clé `modules` d'un scan, schemas.py) :
// {status, data, duration, error}. `data` est la valeur JSON propre au module.
export interface GenericModuleResult {
  status: ModuleRunStatus;
  data: unknown;
  // Secondes.
  duration: number;
  error: string | null;
}

export type FamilyKey = "web" | "tls" | "email" | "dns" | "network" | "identity" | "reputation" | "leaks";
export type FamilyState = "ok" | "warning" | "critical" | "unmeasured" | "skipped" | "info";

export interface FamilySummary {
  state: FamilyState;
  grade: string | null;
  summary: string;
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  severity: Severity;
  family: FamilyKey;
  module: ModuleName;
  message: string;
}

export interface CriterionScore {
  score: number;
  max: number;
  detail?: string | null;
  measured?: boolean;
  counted?: boolean;
  applicable?: boolean;
  // false : le module du critère n'a pas été lancé (profil de scan) ; absent sinon.
  launched?: boolean;
}

export interface Penalty {
  key?: string;
  label: string;
  points: number;
  severity?: string;
}

export interface SecurityScore {
  version?: number;
  score?: number | null;
  max_score?: number;
  grade?: string;
  grade_reason?: string | null;
  breakdown?: Record<string, CriterionScore>;
  coverage?: number | null;
  measured_points?: number;
  measured_max?: number;
  confidence?: "high" | "medium" | "low" | null;
  penalties?: Penalty[];
  grade_cap?: string | null;
  grade_cap_reasons?: string[];
}

export interface MeasuredResult {
  measured?: boolean;
  skipped?: boolean;
  error?: string | null;
}

export interface MxRecord {
  priority?: number;
  value?: string;
  null_mx?: boolean;
}

export interface SoaRecord {
  mname?: string;
  rname?: string;
  serial?: number;
  refresh?: number;
  retry?: number;
  expire?: number;
  minimum?: number;
}

export interface DnsRecords extends MeasuredResult {
  A?: string[];
  AAAA?: string[];
  MX?: MxRecord[];
  NS?: string[];
  TXT?: string[];
  CNAME?: string[];
  SOA?: SoaRecord[];
  DMARC?: string[];
  dmarc_source?: string | null;
  errors?: Record<string, string>;
  nxdomain?: boolean;
  wildcard?: boolean | null;
  notes?: string[];
}

export interface Subdomain {
  subdomain: string;
  ip?: string | null;
  resolution?: "resolved" | "unresolved" | "not_tested";
  wildcard?: boolean;
}

export interface HeaderCheck {
  value?: string | null;
  status: string;
  detail?: string | null;
}

export interface SecurityHeaders extends MeasuredResult {
  headers_found?: Record<string, string>;
  headers_missing?: string[];
  score?: string;
  counts?: { ok?: number; weak?: number; invalid?: number; missing?: number; total?: number } | null;
  checks?: Record<string, HeaderCheck>;
  url?: string | null;
  https?: boolean;
  https_downgrade?: boolean;
  off_site_redirect?: string | null;
}

export interface TlsCertificate extends MeasuredResult {
  https?: boolean;
  valid?: boolean;
  verify_error?: string | null;
  verify_code?: number | null;
  subject?: string;
  issuer_org?: string;
  issuer_cn?: string;
  serial_number?: string;
  version?: number | string;
  not_before?: string;
  not_after?: string;
  days_remaining?: number | null;
  san?: string[];
  protocol?: string | null;
  cipher?: string | null;
  cipher_bits?: number | null;
}

export interface Technology {
  name: string;
  category?: string;
}

export interface GeoData extends MeasuredResult {
  ip?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  zip?: string;
  lat?: number | null;
  lon?: number | null;
  timezone?: string;
  isp?: string;
  org?: string;
  as_info?: string;
  anycast?: boolean;
}

export interface WhoisData extends MeasuredResult {
  queried_domain?: string | null;
  registrar?: string | null;
  creation_date?: string | null;
  expiration_date?: string | null;
  updated_date?: string | null;
  name_servers?: string[];
  status?: string[];
  dnssec?: string | null;
  registrant?: string | null;
  emails?: string[];
  registered?: boolean | null;
}

export interface OpenPort {
  port: number;
  state?: string;
  service?: string;
}

export interface SpfResult {
  domain?: string | null;
  apex_domain?: string | null;
  apex_record?: string | null;
  found?: boolean | null;
  record?: string | null;
  all?: string | null;
  issues?: string[];
  grade?: string | null;
  error?: string | null;
}

export interface DmarcResult {
  found?: boolean | null;
  record?: string | null;
  policy?: string | null;
  subdomain_policy?: string | null;
  pct?: number | null;
  source?: string | null;
  inherited?: boolean;
  issues?: string[];
  grade?: string | null;
  error?: string | null;
}

export interface DkimResult {
  found?: boolean | null;
  selectors_found?: string[];
  revoked_selectors?: string[];
  selectors_tested?: string[];
  wildcard?: string | null;
  issues?: string[];
  error?: string | null;
}

export interface SimpleRecordResult {
  found?: boolean | null;
  record?: string | null;
  error?: string | null;
}

export interface EmailSecurity extends MeasuredResult {
  domain?: string;
  dmarc_domain?: string;
  null_mx?: boolean | null;
  spf?: SpfResult;
  dmarc?: DmarcResult;
  dkim?: DkimResult;
  mta_sts?: SimpleRecordResult;
  tls_rpt?: SimpleRecordResult;
  overall_grade?: string;
  recommendations?: string[];
  notes?: string[];
  partial?: boolean;
}

export interface Waf extends MeasuredResult {
  detected?: boolean;
  waf_name?: string | null;
  confidence?: string;
  evidence?: string[];
  cdn_detected?: boolean;
  cdn_name?: string | null;
  cdn_evidence?: string[];
  off_site_redirect?: string | null;
}

export interface RedirectHop {
  url?: string;
  status_code?: number;
  server?: string;
  error?: string | null;
  same_site?: boolean;
}

export interface RedirectChain extends MeasuredResult {
  chain?: RedirectHop[];
  total_hops?: number;
  forces_https?: boolean | null;
  final_url?: string | null;
  leaves_site?: boolean;
  https_chain?: RedirectHop[];
  https_downgrade?: boolean;
  http_available?: boolean;
  https_available?: boolean;
  warnings?: string[];
}

export interface WebFile {
  found?: boolean | null;
  error?: string | null;
}

export interface WebFiles extends MeasuredResult {
  robots_txt?: WebFile & { content?: string | null; disallowed?: string[]; sitemaps?: string[] };
  sitemap_xml?: WebFile & { url_count?: number; truncated?: boolean; is_index?: boolean };
  security_txt?: WebFile & { content?: string | null; contact?: string | null };
  partial?: boolean;
}

export interface Cookie {
  name: string;
  secure?: boolean;
  httponly?: boolean;
  samesite?: string | null;
  path?: string;
  domain?: string | null;
  expired?: boolean;
  issues?: string[];
}

export interface CookieSecurity extends MeasuredResult {
  cookies?: Cookie[];
  issues?: string[];
  score?: string;
  cookies_present?: boolean;
}

export interface Cors extends MeasuredResult {
  cors_enabled?: boolean;
  misconfigured?: boolean;
  allows_any_origin?: boolean;
  allows_credentials_with_wildcard?: boolean;
  reflects_origin?: boolean;
  reflects_with_credentials?: boolean;
  reflected_origin?: string | null;
  severity?: string | null;
  details?: string[];
  url?: string | null;
  off_site_redirect?: string | null;
  origin_tests?: { total?: number; succeeded?: number; errors?: string[] };
  partial?: boolean;
}

export interface ReverseDns extends MeasuredResult {
  ptr?: string | null;
  aliases?: string[];
}

export interface TakeoverEntry {
  subdomain: string;
  cname?: string;
  service?: string;
  provider?: string | null;
  risk?: string;
  confirmed?: boolean;
  fingerprint_matched?: boolean;
  cname_nxdomain?: boolean;
  status_code?: number | null;
  evidence?: string;
}

export interface NetworkExtended extends MeasuredResult {
  reverse_ip_neighbors?: string[];
  neighbors_total?: number;
  neighbors_truncated?: boolean;
  neighbors_error?: string | null;
  asn_info?: { asn?: string; org?: string | null; hostname?: string | null; anycast?: boolean };
  asn_error?: string | null;
}

// Catalogue des modules (GET /api/modules), miroir de domainrecon/api/routes/modules.py.
export interface CatalogKey {
  name: string;
  service: string;
  label: string;
  required: boolean;
  free_text: boolean;
  hidden: boolean;
  configured: boolean;
}

export interface CatalogModule {
  name: string;
  family: string;
  category: string;
  requires_authorization: boolean;
  keys?: CatalogKey[];
  key_tests?: string[];
  wave?: number;
  depends_on?: string[];
  quick?: boolean;
  optional?: boolean;
  timeout?: number | null;
  criteria?: Array<{ criterion: string; weight: number }>;
  help: { title: string; checks: string; why: string };
  // « Comment corriger » du module, dans la langue de la requête ; chaque partie est ABSENTE
  // quand le module ne la renseigne pas (jamais null ni vide).
  // fix : étapes, une par ligne ; fix_snippet : extrait à copier (variantes « # libellé ») ;
  // fix_ref : adresse https de la documentation officielle.
  fix?: string;
  fix_snippet?: string;
  fix_ref?: string;
}

export interface ModulesResponse {
  modules: CatalogModule[];
  families: string[];
  categories?: string[];
  profiles?: string[];
  unavailable?: string[];
}

// Profils de scan de l'API.
export type ScanProfile = "rapide" | "complet" | "personnalise";

export type ScanStatus = "success" | "partial" | "error";

export interface ScanResponse {
  id: number;
  domain: string;
  ip_address: string | null;
  dns_records: DnsRecords;
  subdomains: Subdomain[];
  security_headers: SecurityHeaders;
  whois_data: WhoisData;
  geo_data: GeoData;
  tls_certificate: TlsCertificate;
  open_ports: OpenPort[];
  technologies: Technology[];
  email_security: EmailSecurity;
  waf: Waf;
  redirect_chain: RedirectChain;
  web_files: WebFiles;
  cookie_security: CookieSecurity;
  cors: Cors;
  reverse_dns: ReverseDns;
  subdomain_takeover: TakeoverEntry[];
  network_extended: NetworkExtended;
  security_score: SecurityScore;
  module_status: Partial<Record<ModuleName, ModuleStatusEntry>>;
  // Socle v2 des modules : null (ou absents) pour un scan d'avant la v2, dont les
  // résultats sont dans les champs ci-dessus, lus en priorité.
  // Résultats des modules du registre, par nom (les noms dépassent ModuleName).
  modules?: Record<string, GenericModuleResult> | null;
  // Profil du scan : « rapide », « complet » ou « personnalise ».
  profile?: string | null;
  // Noms des modules lancés, dans l'ordre d'exécution ; null : liste inconnue.
  modules_launched?: string[] | null;
  scan_duration: number | null;
  screenshot_path: string | null;
  tags: string[];
  notes: string | null;
  scan_timestamp: string;
  status: string;
  error_message: string | null;
  // Calculés par l'API à chaque lecture (spec §5.5) ; défensifs côté interface.
  families: Partial<Record<FamilyKey, FamilySummary>>;
  findings: Finding[];
}

export interface ScanSummary {
  id: number;
  domain: string;
  ip_address: string | null;
  subdomains_count: number | null;
  open_ports_count: number | null;
  security_score: SecurityScore;
  tags: string[];
  scan_timestamp: string;
  status: string;
}

export interface HistoryResponse {
  total: number;
  scans: ScanSummary[];
}

export interface DnsChange {
  added: unknown[];
  removed: unknown[];
}

export interface TimelineEntry {
  scan_id: number;
  timestamp: string;
  status: string;
  ip_address: string | null;
  subdomains_count: number | null;
  open_ports_count: number | null;
  security_score: number | null;
  grade: string | null;
  coverage: number | null;
  // null : scan antérieur à ce champ (voir timelineScoreView).
  measured_max: number | null;
  score_version: number | null;
  dns_changes: Record<string, DnsChange> | null;
}

export interface RelatedDomain {
  domain: string;
  total_scans: number;
}

export interface TimelineResponse {
  domain: string;
  apex: string;
  total_scans: number;
  timeline: TimelineEntry[];
  related_domains: RelatedDomain[];
}

export type JobState = "running" | "done" | "failed" | "cancelled";

export interface JobStatus {
  id: string;
  domain: string;
  status: JobState;
  scan_id: number | null;
  done: number;
  total: number;
}

export interface JobStarted {
  id: string;
  status: "running";
}

export type JobEvent =
  | { event: "module"; data: { name: ModuleName; family: FamilyKey; status: ModuleRunStatus; duration: number } }
  | { event: "progress"; data: { done: number; total: number } }
  | { event: "done"; data: { scan_id: number } }
  | { event: "failed"; data: { code: string | null; params: Record<string, unknown>; detail: string } }
  | { event: "cancelled"; data: Record<string, never> };

export interface HealthResponse {
  api: string;
  database: string;
  version: string;
}

export interface SystemInfo {
  version: string;
  data_dir: string;
  portable: boolean;
  frozen: boolean;
  // Absent d'un serveur plus ancien ; false quand API_DOCS désactive /api/docs.
  docs_enabled?: boolean;
}

export interface ErrorBody {
  detail?: unknown;
  code?: string | null;
  params?: Record<string, unknown>;
}
