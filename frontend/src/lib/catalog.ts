import type { CatalogModule, FamilyKey, ModulesResponse } from "../api/types";
import { FAMILY_KEYS, FAMILY_MODULES, isFamilyKey, MODULE_FAMILY, MODULE_NAMES } from "./families";
import { FAMILY_CRITERIA } from "./familyScore";

// Catalogue des modules vu par l'interface : construit depuis GET /api/modules, ou, tant
// qu'il n'a pas répondu, depuis le repli statique des 18 modules historiques. Toute
// l'interface lit familles et modules ICI, jamais dans des listes recopiées.
export interface Catalog {
  // Vrai quand les données viennent du serveur.
  live: boolean;
  families: readonly FamilyKey[];
  // Noms de tous les modules, dans l'ordre d'exécution.
  moduleNames: readonly string[];
  total: number;
  modules(family: FamilyKey): readonly string[];
  familyOf(name: string): FamilyKey | undefined;
  info(name: string): CatalogModule | undefined;
  // Titre rendu dans la langue de la requête (absent du repli statique).
  title(name: string): string | undefined;
  // Critères du barème de la famille (clés de security_score.breakdown).
  criteria(family: FamilyKey): readonly string[];
}

function assemble(
  live: boolean,
  families: readonly FamilyKey[],
  list: readonly CatalogModule[],
  // Ordre des modules à l'intérieur de chaque famille (par défaut : celui de `list`).
  grouping?: Readonly<Record<FamilyKey, readonly string[]>>,
): Catalog {
  const byName = new Map(list.map((module) => [module.name, module]));
  const grouped = new Map<FamilyKey, string[]>(families.map((family) => [family, []]));
  for (const module of list) {
    if (isFamilyKey(module.family)) grouped.get(module.family)?.push(module.name);
  }
  if (grouping) for (const family of families) grouped.set(family, [...grouping[family]]);
  const criteria = new Map<FamilyKey, string[]>(
    families.map((family) => [family, [...FAMILY_CRITERIA[family]]]),
  );
  for (const module of list) {
    if (!isFamilyKey(module.family)) continue;
    const own = criteria.get(module.family);
    for (const item of module.criteria ?? []) {
      if (own && !own.includes(item.criterion)) own.push(item.criterion);
    }
  }
  return {
    live,
    families,
    moduleNames: list.map((module) => module.name),
    total: list.length,
    modules: (family) => grouped.get(family) ?? [],
    familyOf: (name) => {
      const family = byName.get(name)?.family;
      if (isFamilyKey(family)) return family;
      return Object.hasOwn(MODULE_FAMILY, name) ? MODULE_FAMILY[name] : undefined;
    },
    info: (name) => byName.get(name),
    title: (name) => byName.get(name)?.help?.title || undefined,
    criteria: (family) => criteria.get(family) ?? FAMILY_CRITERIA[family],
  };
}

// Modules actifs : sondes envoyées à la cible, lancés seulement sur une cible déclarée autorisée.
const ACTIVE_MODULES: readonly string[] = ["open_ports", "subdomain_takeover"];

function staticModules(): CatalogModule[] {
  return MODULE_NAMES.map((name) => ({
    name,
    family: MODULE_FAMILY[name],
    category: ACTIVE_MODULES.includes(name) ? "actif" : "passif",
    requires_authorization: ACTIVE_MODULES.includes(name),
    help: { title: "", checks: "", why: "" },
  }));
}

// Les 18 modules historiques : ordre d'exécution de MODULE_NAMES, ordre de FAMILY_MODULES par famille.
export const STATIC_CATALOG: Catalog = assemble(
  false,
  FAMILY_KEYS,
  staticModules(),
  FAMILY_MODULES,
);

// Catalogue du serveur. Une famille inconnue de l'interface est ignorée (pas d'icône ni
// de texte) ; les familles absentes de la réponse gardent leur place par défaut.
export function buildCatalog(response: ModulesResponse | undefined | null): Catalog {
  const modules = response?.modules;
  if (!Array.isArray(modules) || modules.length === 0) return STATIC_CATALOG;
  const valid = modules.filter((module) => module && typeof module.name === "string" && isFamilyKey(module.family));
  const served = (response?.families ?? []).filter(isFamilyKey);
  const families = served.length ? [...served, ...FAMILY_KEYS.filter((key) => !served.includes(key))] : FAMILY_KEYS;
  return assemble(true, families, valid);
}

// « hibp_leaks » → « Hibp leaks » : dernier recours quand ni la traduction ni le catalogue
// ne donnent de titre.
export function humanizeKey(key: string): string {
  const text = key.replace(/[_-]+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : key;
}

// Libellé d'un module : traduction de l'interface (18 historiques), sinon titre du
// catalogue (déjà dans la langue de la requête), sinon la clé lisible.
export function moduleLabel(t: (key: string, options?: Record<string, unknown>) => string, catalog: Catalog, name: string): string {
  return t(`modules.${name}`, { defaultValue: catalog.title(name) || humanizeKey(name) });
}
