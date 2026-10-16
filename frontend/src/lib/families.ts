import type { FamilyKey, LegacyModuleName } from "../api/types";

// Repli STATIQUE : les 18 modules historiques répartis comme dans
// domainrecon/scanner/families.py. La source de vérité est le catalogue du serveur
// (GET /api/modules, voir lib/catalog.ts) : ces listes servent tant qu'il n'a pas
// répondu (ou si l'API est plus ancienne), et aux modules à composant dédié.
// Ordre d'affichage des familles : celui du serveur (registry.FAMILIES).
export const FAMILY_KEYS: readonly FamilyKey[] = ["web", "tls", "email", "dns", "network", "identity", "reputation", "leaks"];

export const FAMILY_MODULES: Readonly<Record<FamilyKey, readonly LegacyModuleName[]>> = {
  web: ["security_headers", "cookie_security", "cors", "redirect_chain", "web_files", "technologies", "waf"],
  tls: ["tls_certificate"],
  email: ["email_security"],
  dns: ["dns_records", "subdomains", "subdomain_takeover", "reverse_dns"],
  network: ["open_ports", "geo_data", "network_extended"],
  identity: ["whois_data", "screenshot"],
  // Familles sans module historique : leurs modules viennent du catalogue.
  reputation: [],
  leaks: [],
};

// Ordre de module_status des 18 modules historiques (domainrecon/scanner/orchestrator.py).
export const MODULE_NAMES: readonly LegacyModuleName[] = [
  "dns_records",
  "subdomains",
  "security_headers",
  "tls_certificate",
  "technologies",
  "geo_data",
  "whois_data",
  "open_ports",
  "email_security",
  "waf",
  "redirect_chain",
  "web_files",
  "cookie_security",
  "cors",
  "reverse_dns",
  "network_extended",
  "screenshot",
  "subdomain_takeover",
];

export const TOTAL_MODULES = MODULE_NAMES.length;

export const MODULE_FAMILY = Object.fromEntries(
  FAMILY_KEYS.flatMap((family) => FAMILY_MODULES[family].map((module) => [module, family])),
) as Readonly<Record<string, FamilyKey>>;

export function isFamilyKey(value: string | null | undefined): value is FamilyKey {
  return typeof value === "string" && (FAMILY_KEYS as readonly string[]).includes(value);
}

// Un des 18 modules historiques (composant dédié, champ propre dans le scan).
export function isModuleName(value: unknown): value is LegacyModuleName {
  return typeof value === "string" && (MODULE_NAMES as readonly string[]).includes(value);
}
