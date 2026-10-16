import type { AlertRules, Frequency, WatchChannel } from "../../api/ops";

// Choix proposés pour une surveillance.
export const FREQUENCIES: readonly Frequency[] = ["daily", "weekly", "monthly"];
export const WATCH_CHANNELS: readonly WatchChannel[] = ["center", "desktop", "discord", "slack", "teams", "webhook", "email"];
export const BOOLEAN_RULES = ["grade_drop", "new_findings", "new_port", "new_subdomain"] as const;
export const DEFAULT_RULES: AlertRules = {
  grade_drop: true,
  new_findings: true,
  cert_expiry_days: 14,
  new_port: true,
  new_subdomain: true,
};
