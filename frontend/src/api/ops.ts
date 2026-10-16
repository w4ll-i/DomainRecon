import type { DnsChange, Finding, ScanProfile } from "./types";

// Types des écrans d'exploitation : tableau de bord, comparaison, lots, surveillance,
// notifications, réglages. Miroirs des routes de domainrecon/monitor, notify et api/routes/settings.

export interface TrendPoint {
  scan_id: number;
  timestamp: string;
  status: string;
  score: number | null;
  grade: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export type Frequency = "daily" | "weekly" | "monthly";

export interface WatchInfo {
  id: number;
  enabled: boolean;
  frequency: Frequency;
  next_run_at: string;
  last_status: string | null;
}

export interface DashboardItem {
  domain: string;
  scan_id: number;
  scan_timestamp: string;
  status: string;
  grade: string;
  score: number | null;
  coverage: number | null;
  scans_count: number;
  trend: TrendPoint[];
  findings: SeverityCounts;
  watch: WatchInfo | null;
}

export interface DashboardResponse {
  domains: DashboardItem[];
  totals: {
    domains: number;
    shown: number;
    watched: number;
    average_score: number | null;
    grades: Record<string, number>;
    findings: SeverityCounts;
    with_critical_or_high: number;
  };
}

export interface ScoreShown {
  score: number | null;
  grade: string;
  coverage: number | null;
}

export interface PortEntry {
  port: number;
  service?: string | null;
}

export interface CompareResponse {
  domain: string;
  a: { id: number; timestamp: string; status: string };
  b: { id: number; timestamp: string; status: string };
  comparable: boolean;
  score: { a: ScoreShown; b: ScoreShown; delta: number | null; grade_changed: boolean };
  findings: { new: Finding[]; resolved: Finding[]; unchanged: number } | null;
  dns: Record<string, DnsChange> | null;
  ports: { opened: PortEntry[]; closed: PortEntry[] } | null;
  subdomains: { added: string[]; removed: string[] } | null;
  certificate: {
    changed: boolean;
    fields: Record<string, { a: unknown; b: unknown }>;
    days_remaining: { a: number | null; b: number | null };
  } | null;
  technologies: { added: string[]; removed: string[] } | null;
  changes: string[];
}

export type BatchItemStatus = "queued" | "running" | "done" | "failed" | "cancelled";

export interface BatchItem {
  domain: string;
  status: BatchItemStatus;
  scan_id: number | null;
  job_id: string | null;
  error: string | null;
  grade: string | null;
  score: number | null;
}

export interface BatchView {
  id: string;
  status: string;
  profile: ScanProfile;
  created_at: string;
  total: number;
  counts: Record<BatchItemStatus, number>;
  finished: number;
  items?: BatchItem[];
  rejected?: Array<{ input: string; reason: string }>;
  duplicates?: number;
}

export type WatchChannel = "discord" | "slack" | "teams" | "webhook" | "email" | "desktop" | "center";

export interface AlertRules {
  grade_drop: boolean;
  new_findings: boolean;
  cert_expiry_days: number | null;
  new_port: boolean;
  new_subdomain: boolean;
}

export interface Watch {
  id: number;
  domain: string;
  profile: ScanProfile;
  selected: string[] | null;
  authorized_target: boolean;
  frequency: Frequency;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  last_scan_id: number | null;
  last_status: string | null;
  last_error: string | null;
  rules: AlertRules;
  channels: WatchChannel[];
  lang: "fr" | "en";
  created_at: string;
}

export interface WatchInput {
  domain: string;
  profile?: ScanProfile;
  frequency: Frequency;
  rules: AlertRules;
  channels: WatchChannel[];
  lang: "fr" | "en";
}

export interface SystemTask {
  supported: boolean;
  platform: string;
  installed: boolean;
  command: string | null;
}

export interface NotificationItem {
  id: number;
  created_at: string;
  domain: string;
  scan_id: number | null;
  watch_id: number | null;
  rule: string;
  severity: string;
  message: string;
  is_read: boolean;
  delivery: Record<string, unknown>;
}

export interface NotificationsResponse {
  total: number;
  unread: number;
  items: NotificationItem[];
}

export type ChannelName = "discord" | "slack" | "teams" | "webhook" | "email" | "desktop";

export interface ChannelView {
  name: ChannelName;
  enabled: boolean;
  configured: boolean;
  // Secrets masqués par le serveur (jamais en clair).
  config: Record<string, unknown>;
}

export interface SettingsView {
  api_keys: Record<string, string>;
  scan_timeout: number;
  quick_timeout: number;
  screenshot_enabled: boolean;
  proxy_url: string;
}

export interface SettingsUpdate {
  api_keys?: Record<string, string>;
  scan_timeout?: number;
  quick_timeout?: number;
  screenshot_enabled?: boolean;
  proxy_url?: string;
}

export interface ServiceTestResult {
  service: string;
  success: boolean;
  message: string;
}

export interface VpnStatus {
  connected: boolean | null;
  ip: string | null;
  country: string | null;
  provider: string | null;
  mullvad_cli: boolean;
  message: string;
}

// Résultat de l'import d'une ancienne base (POST /api/import). read = imported + ignored,
// ignored = duplicates + unusable.
export interface ImportResult {
  // Scans lus dans la base envoyée.
  read: number;
  // Scans ajoutés à l'historique.
  imported: number;
  // Scans non importés (doublons et lignes inutilisables).
  ignored: number;
  // Déjà présents (même domaine, même horodatage).
  duplicates: number;
  // Lignes sans domaine ou sans horodatage lisible.
  unusable: number;
  // Colonnes de l'ancienne base sans équivalent, non reprises (50 noms au plus).
  unknown_columns: string[];
}
