import type { ComponentType } from "react";
import type { FamilyKey, Finding, LegacyModuleName, ScanResponse } from "../../api/types";
import type { Catalog } from "../../lib/catalog";
import { isModuleName } from "../../lib/families";
import type { Tone } from "../../lib/tones";
import { DnsRecordsModule, ReverseDnsModule, SubdomainsModule, TakeoverModule } from "./modules/dns";
import { EmailModule } from "./modules/email";
import { GenericModule } from "./modules/generic";
import { WhoisModule } from "./modules/identity";
import { GeoModule, NetworkExtModule, PortsModule } from "./modules/network";
import { LazyNetworkGraph } from "./modules/lazyParts";
import { NotesTags } from "./modules/NotesTags";
import { ScreenshotModule } from "./modules/Screenshot";
import { TlsModule } from "./modules/tls";
import {
  CookiesModule,
  CorsModule,
  HeadersModule,
  RedirectsModule,
  TechnologiesModule,
  WafModule,
  WebFilesModule,
} from "./modules/web";

// Un onglet de l'écran d'une famille : un module (ou, pour la carte réseau et les
// notes, un bloc propre à la famille).
export interface FamilyTab {
  // Identifiant dans l'adresse (/scans/:id/:family/:module) : le nom du module du
  // scan, ou « graph » et « notes » pour les blocs qui n'en sont pas un.
  key: string;
  // Clé i18n du libellé : modules.<nom> pour un module, family.tabs.* sinon.
  labelKey: string;
  // Le nom d'un module du scan : ses constats se comptent sur l'onglet (absent : aucun constat).
  module?: string;
  // Titre du catalogue, quand le libellé n'est pas traduit par l'interface (module sans composant dédié).
  title?: string;
  // `module` : le module de l'onglet, pour les composants génériques.
  component: ComponentType<{ scan: ScanResponse; module?: string }>;
}

const moduleTab = (name: LegacyModuleName, component: FamilyTab["component"]): FamilyTab => ({
  key: name,
  labelKey: `modules.${name}`,
  module: name,
  component,
});

// Onglets de chaque famille, dans l'ordre d'affichage (le premier est l'onglet par
// défaut). Chaque module historique (lib/families.ts, FAMILY_MODULES) a son composant
// dédié ; les autres modules du catalogue s'ajoutent par withCatalogTabs (affichage générique).
export const FAMILY_TABS: Readonly<Record<FamilyKey, readonly FamilyTab[]>> = {
  web: [
    moduleTab("security_headers", HeadersModule),
    moduleTab("cookie_security", CookiesModule),
    moduleTab("cors", CorsModule),
    moduleTab("redirect_chain", RedirectsModule),
    moduleTab("web_files", WebFilesModule),
    moduleTab("technologies", TechnologiesModule),
    moduleTab("waf", WafModule),
  ],
  tls: [moduleTab("tls_certificate", TlsModule)],
  email: [moduleTab("email_security", EmailModule)],
  dns: [
    { key: "graph", labelKey: "family.tabs.graph", component: LazyNetworkGraph },
    moduleTab("dns_records", DnsRecordsModule),
    moduleTab("subdomains", SubdomainsModule),
    moduleTab("subdomain_takeover", TakeoverModule),
    moduleTab("reverse_dns", ReverseDnsModule),
  ],
  network: [moduleTab("geo_data", GeoModule), moduleTab("open_ports", PortsModule), moduleTab("network_extended", NetworkExtModule)],
  identity: [
    moduleTab("whois_data", WhoisModule),
    moduleTab("screenshot", ScreenshotModule),
    { key: "notes", labelKey: "family.tabs.notes", component: NotesTags },
  ],
  reputation: [],
  leaks: [],
};

// Onglet affiché : celui de l'adresse, ou le premier quand l'adresse n'en nomme aucun
// (ou un onglet qui n'existe pas dans cette famille). Undefined pour une famille sans onglet.
export function activeFamilyTab(
  family: FamilyKey,
  key: string | undefined,
  tabs: readonly FamilyTab[] = FAMILY_TABS[family],
): FamilyTab | undefined {
  return tabs.find((tab) => tab.key === key) ?? tabs[0];
}

// Onglet générique d'un module du catalogue sans composant dédié.
const genericTab = (name: string, catalog: Catalog): FamilyTab => ({
  key: name,
  labelKey: `modules.${name}`,
  module: name,
  title: catalog.title(name),
  component: GenericModule,
});

// Onglets d'une famille : ceux des modules historiques, puis un onglet générique pour
// chaque autre module du catalogue (dans son ordre), avant le bloc « notes » s'il y en a un.
export function withCatalogTabs(base: readonly FamilyTab[], family: FamilyKey, catalog: Catalog): FamilyTab[] {
  const known = new Set(base.map((tab) => tab.key));
  const extra = catalog
    .modules(family)
    .filter((name) => !isModuleName(name) && !known.has(name))
    .map((name) => genericTab(name, catalog));
  if (extra.length === 0) return [...base];
  const notes = base.findIndex((tab) => !tab.module && tab.key === "notes");
  return notes < 0 ? [...base, ...extra] : [...base.slice(0, notes), ...extra, ...base.slice(notes)];
}

// Compte et ton de la pastille d'un onglet : les constats du module, du plus grave
// (critique ou élevée : rouge ; moyenne : orange ; faible : neutre). Aucun constat : pas de pastille.
export function tabFindings(findings: readonly Finding[] | null | undefined, tab: FamilyTab): { count: number; tone: Tone } | null {
  if (!tab.module) return null;
  const own = (findings ?? []).filter((finding) => finding.module === tab.module);
  if (!own.length) return null;
  const severe = own.some((finding) => finding.severity === "critical" || finding.severity === "high");
  const medium = own.some((finding) => finding.severity === "medium");
  return { count: own.length, tone: severe ? "critical" : medium ? "warning" : "neutral" };
}
