import type { FamilyKey, ScanResponse } from "../../api/types";
import { type Catalog, STATIC_CATALOG } from "../../lib/catalog";
import { scanModuleState } from "../../lib/moduleState";

const isCount = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;

// Numéro d'AS du bandeau de métriques : « AS15133 ». Source : le module réseau
// étendu (asn_info.asn, avec ou sans le préfixe « AS »), sinon la ligne d'AS de la
// géolocalisation (« AS15133 Edgecast Inc. »). null quand aucune source ne le donne.
export function scanAsn(scan: Pick<ScanResponse, "network_extended" | "geo_data">): string | null {
  const direct = scan.network_extended?.asn_info?.asn;
  if (typeof direct === "string" && direct.trim()) {
    const value = direct.trim();
    if (/^\d+$/.test(value)) return `AS${value}`;
    const prefixed = value.match(/^AS(\d+)\b/i);
    return prefixed ? `AS${prefixed[1]}` : value;
  }
  const line = scan.geo_data?.as_info;
  const found = typeof line === "string" ? line.match(/\bAS(\d+)\b/i) : null;
  return found ? `AS${found[1]}` : null;
}

// Nombre d'éléments d'un module de liste (sous-domaines, ports), selon la règle du
// serveur (history._module_count) : null quand le module n'a rien mesuré (échec, délai
// dépassé, sans objet : sa liste vide ne dit pas « rien trouvé »), sinon la taille de la
// liste, ou le total trouvé avant la coupe d'une liste plafonnée s'il est plus grand.
export function moduleCount(scan: ScanResponse, module: "subdomains" | "open_ports"): number | null {
  if (scanModuleState(scan, module).status !== "ok") return null;
  const list = scan[module];
  if (!Array.isArray(list)) return null;
  const found = module === "subdomains" ? scan.module_status?.subdomains?.total_found : undefined;
  return isCount(found) ? Math.max(list.length, Math.trunc(found)) : list.length;
}

// Modules d'une famille qui ont rendu un résultat (statut « mesuré »), sur ceux qu'elle compte.
//  Un module non lancé (profil du scan) ne compte pas dans le total.
export function familyModuleCount(
  scan: ScanResponse,
  family: FamilyKey,
  catalog: Catalog = STATIC_CATALOG,
): { measured: number; total: number } {
  const modules = catalog.modules(family).filter((name) => scanModuleState(scan, name).status !== "not_launched");
  const measured = modules.filter((name) => scanModuleState(scan, name).status === "ok").length;
  return { measured, total: modules.length };
}
